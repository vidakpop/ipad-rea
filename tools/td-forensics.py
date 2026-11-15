#!/usr/bin/env python3
"""td-forensics.py — byte-level compare of module TDs vs kernel TDs on the EP0 ring.

On the live fresh DFU device with WHO-verified capture:
  1. dump rows (baseline, retired kernel TDs)
  2. ONE module GETSTATUS push (with status)
  3. dump rows again (module TD now at the enqueue region)
  4. kernel kick GET
  5. dump once more
Eyeball-diff: the healthy kernel rows (SETUP=2, DATA=3, STATUS=4 with
fields) vs the module's rows - find the structural killer.
"""
import importlib.util
import os
import struct

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sp = importlib.util.spec_from_file_location(
    'pwn', os.path.join(REPO, 'tools/checkm8-a5-pwn.py'))
P = importlib.util.module_from_spec(sp)
sp.loader.exec_module(P)

import fcntl
import ctypes

IOC_PUSH = (1 << 30) | (32 << 16) | (ord('R') << 8) | 1
NDUMP = 48
RD_SIZE = 6 * 4 + NDUMP * 4 * 4 + 1024
IOC_RINGDUMP = (2 << 30) | (RD_SIZE << 16) | (ord('R') << 8) | 6
IOC_WHO = (2 << 30) | (16 << 16) | (ord('R') << 8) | 11


def dump(fd, label, lo=0, hi=NDUMP):
    buf = bytearray(RD_SIZE)
    fcntl.ioctl(fd, IOC_RINGDUMP, buf, True)
    vals = struct.unpack("<%dI" % (RD_SIZE // 4), bytes(buf))
    head = dict(enq=vals[0], cyc=vals[1], hwdeq=vals[2], epst=vals[3],
                slot=vals[4], n=vals[5])
    print('[%s] enq=%d cyc=%d hwdeq=0x%x epst=%d slot=%d'
          % (label, head['enq'], head['cyc'], head['hwdeq'],
             head['epst'], head['slot']))
    for i in range(lo, min(hi, NDUMP)):
        w0, w1, w2, w3 = vals[6 + i * 4: 6 + i * 4 + 4]
        mark = ' <ENQ' if i == head['enq'] else ''
        print('  %3d  c%d  t%2d  %08x %08x %08x %08x%s'
              % (i, w3 & 1, (w3 >> 10) & 0x3f, w0, w1, w2, w3, mark))


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


def main():
    fd = os.open('/dev/raw0', os.O_RDWR)

    wb = bytearray(16)
    fcntl.ioctl(fd, IOC_WHO, wb, True)
    busnum, devnum, vid, pid = struct.unpack('<4I', bytes(wb))
    print('WHO: bus %d addr %d vid %04x pid %04x' % (busnum, devnum, vid, pid))
    if vid != 0x05ac or pid != 0x1227:
        print('CAPTURE WRONG - not the DFU iPad; abort')
        return 1

    usb = P.LibUSB()
    P.LibUSB._current = usb
    dev, handle, dsc, serial = P.acquire(usb, want_serial=False)
    print('open:', usb.describe(dev))

    print('--- BASELINE (retired kernel TDs) ---')
    dump(fd, 'base')

    print('--- AFTER module GETSTATUS push ---')
    rc = push(fd, bytes([0xA1, 0x03, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00]),
              b'\x00' * 6, has_status=1, dir_in=1)
    print('push rc=%d' % rc)
    dump(fd, 'pushed')

    print('--- AFTER kernel kick GET (8B) ---')
    krc, kd = usb.ctrl_in(handle, 0x80, 0x06, 0x0100, 0x0000, 8, 1500)
    print('kick rc=%s' % krc)
    dump(fd, 'kick')

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
