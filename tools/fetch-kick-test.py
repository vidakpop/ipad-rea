#!/usr/bin/env python3
"""fetch-kick-test.py — THE fetch matrix, minimal form.

Question: does a module-pushed control TD execute on the wire when a
kernel URB runs alongside it (the historical "kernel-URB kick")?

Method (fresh dance required):
  1. wait for fresh DFU (sysfs only, no traffic)
  2. pre-readback: show the coherent buffer state
  3. module-push ONE with-status GETSTATUS (IN 6 bytes) - queued, no CYC
  4. THE KICK: one tiny usbfs control GET (8-byte descriptor head)
  5. post-readback: if bytes [0:6] became DFU state fields, the module
     TD executed on the wire -> the fetch interleave is BORN.
  6. variant B: module-push serial GET (0x80) + kick + readback
"""
import argparse
import importlib.util
import os
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sp = importlib.util.spec_from_file_location(
    'pwn', os.path.join(REPO, 'tools/checkm8-a5-pwn.py'))
P = importlib.util.module_from_spec(sp)
sp.loader.exec_module(P)

import fcntl
import ctypes

IOC_PUSH = (1 << 30) | (32 << 16) | (ord('R') << 8) | 1
IOC_STATE = (2 << 30) | (40 << 16) | (ord('R') << 8) | 3
RB_SIZE = 4 + 4 + 0x1000
IOC_RW = (3 << 30) | (RB_SIZE << 16) | (ord('R') << 8) | 7


def push(fd, setup, data, has_status, dir_in):
    arr = (ctypes.c_ubyte * max(len(data), 1)).from_buffer_copy(
        bytes(data) if data else b'\x00')
    txn = struct.pack('<8sI4BQII', bytes(setup), len(data),
                      1 if data else 0, has_status, 1 if dir_in else 0, 0,
                      ctypes.addressof(arr), 0, 0)
    try:
        fcntl.ioctl(fd, IOC_PUSH, txn, True)
        _ = arr
        return 0
    except OSError as e:
        _ = arr
        return -e.errno


def readback(fd, n):
    rb = bytearray(RB_SIZE)
    struct.pack_into('<I', rb, 0, n)
    fcntl.ioctl(fd, IOC_RW, rb, True)
    st, = struct.unpack_from('<I', rb, 4)
    return st, bytes(rb[8:8 + n])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--wait', type=float, default=0.0)
    args = ap.parse_args()

    if args.wait:
        print('put the iPad in DFU now (fresh dance after force-restart)')
        syspath, sserial = P.sysfs_dfu(timeout=args.wait)
        if syspath is None:
            print('no DFU appeared')
            return 1
        print('DFU arrived:', syspath)
    else:
        syspath, sserial = P.sysfs_dfu(timeout=2.0)
        if not syspath:
            print('no DFU on bus; pass --wait')
            return 1

    usb = P.LibUSB()
    P.LibUSB._current = usb
    fd = os.open('/dev/raw0', os.O_RDWR)
    buf = bytearray(40)
    fcntl.ioctl(fd, IOC_STATE, buf, True)
    f = struct.unpack_from('<QIIIIIIII', buf, 0)
    print('[module] slot=%d state=%d' % (f[1], f[5]))
    if not f[5]:
        print('[module] no capture - dance BEFORE me next time')
        os.close(fd)
        return 1

    st, d = readback(fd, 16)
    print('[pre] readback status=%d first16: %s' % (st, d.hex()))

    dev, handle, dsc, serial = P.acquire(usb, want_serial=False)
    print('[open] %s' % usb.describe(dev))

    # ---- TEST A: module GETSTATUS (IN 6B + status) + kernel kick ------
    rc = push(fd, bytes([0xA1, 0x03, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00]),
              b'\x00' * 6, has_status=1, dir_in=1)
    print('[A] module GETSTATUS push rc=%d' % rc)
    krc, kd = usb.ctrl_in(handle, 0x80, 0x06, 0x0100, 0x0000, 8, 1500)
    print('[A] kick urb rc=%s data=%s' % (krc, kd.hex() if krc > 0 else '-'))
    st, d = readback(fd, 16)
    print('[A] READBACK status=%d bytes: %s' % (st, d.hex()))
    if d[:6] != b'\x00' * 6:
        print('*** A VERDICT: SERVED - the fetch interleave WORKS ***')
    else:
        print('*** A VERDICT: zeros - module TD still not fetched ***')

    # ---- TEST B: module serial GET (IN 0x80 + status) + kick ------------
    rc = push(fd, bytes([0x80, 0x06, 0x03, 0x03, 0x0A, 0x04, 0x80, 0x00]),
              b'\x00' * 0x80, has_status=1, dir_in=1)
    print('[B] module serial GET push rc=%d' % rc)
    krc, kd = usb.ctrl_in(handle, 0x80, 0x06, 0x0100, 0x0000, 8, 1500)
    print('[B] kick urb rc=%s' % krc)
    st, d = readback(fd, 32)
    print('[B] READBACK status=%d first32: %s' % (st, d.hex()))
    if d[2:8] != b'\x00' * 6:
        try:
            txt = d[2:2 + 40].decode('utf-16-le', errors='replace')
            print('[B] utf16: %r' % txt[:30])
        except Exception:
            pass
        print('*** B VERDICT: big serve through module TD + kick ***')
    else:
        print('*** B VERDICT: zeros ***')

    os.close(fd)
    return 0


if __name__ == '__main__':
    sys.exit(main())
