#!/usr/bin/env python3
"""Stall-class scouting ladder - one complete control TD per run.

The checkm8 A5 heap feng-shui needs the ROM to allocate its per-request
io_buffer and never free it. The sketch (and our cancelled-usbfs era)
achieves that with host-side mid-transfer aborts - a class that is
banned on this box (two crashes) and impossible with hand-queued xHCI
TDs anyway (dangling TDs never execute).

This ladder tests the last host-clean alternative: request shapes the
ROM STALLS. A stall is the device's own decision - a COMPLETE xHCI
transaction (CC_STALL), no host abandonment anywhere. If the ROM's
stall path frees late or never, the leak primitive exists with zero
cancels.

Per run (one shape):
  STATE + RINGDUMP baseline -> PUSH complete TD -> settle ->
  STATE + RINGDUMP (deq advance, ep_state) -> READBACK staging (IN
  shapes: exactly what the ROM put on the wire, incl. anything past
  the expected length).
Ladder safety: on ep halt (state 2) or a frozen dequeue the script
writes /tmp/scout-HALT and exits 2; the orchestrator must STOP (no
resets on a dirtied ring - physical recovery only).
"""
import argparse
import ctypes
import fcntl
import os
import struct
import sys
import time

NDUMP = 48
RD_SIZE = 6 * 4 + NDUMP * 4 * 4 + 1024
ST_SIZE = 40
RB_SIZE = 8 + 4096

IOC_PUSH = (1 << 30) | (32 << 16) | (ord("R") << 8) | 1
IOC_STATE = (2 << 30) | (ST_SIZE << 16) | (ord("R") << 8) | 3
IOC_RINGDUMP = (2 << 30) | (RD_SIZE << 16) | (ord("R") << 8) | 6
IOC_READBACK = (3 << 30) | (RB_SIZE << 16) | (ord("R") << 8) | 7


def state(fd):
    buf = bytearray(ST_SIZE)
    fcntl.ioctl(fd, IOC_STATE, buf, True)
    f = struct.unpack("<QIIIIIIII", buf)
    return dict(xhci=f[0], slot=f[1], free=f[3], cyc=f[4], captured=f[5],
                pushed=f[6], deq_off=f[7], ep0=f[8])


def ringdump(fd):
    buf = bytearray(RD_SIZE)
    fcntl.ioctl(fd, IOC_RINGDUMP, buf, True)
    vals = struct.unpack("<%dI" % (RD_SIZE // 4), buf)
    head = dict(enq=vals[0], cyc=vals[1], hwdeq=vals[2], epst=vals[3],
                slot=vals[4], ntrb=vals[5])
    return head, vals


def readback(fd, n=4096):
    buf = bytearray(RB_SIZE)
    struct.pack_into("<I", buf, 0, min(n, 4096))
    fcntl.ioctl(fd, IOC_READBACK, buf, True)
    status = struct.unpack_from("<I", buf, 4)[0]
    return status, bytes(buf[8:8 + min(n, 4096)])


def push(fd, setup, data_len, dir_in, has_data=True, has_status=True):
    cdata = (ctypes.c_ubyte * max(64, data_len or 64))()
    txn = struct.pack("<8sIBBBBQII", setup, data_len, 1 if has_data else 0,
                      1 if has_status else 0, 1 if dir_in else 0, 0,
                      ctypes.addressof(cdata), 0, 0)
    return fcntl.ioctl(fd, IOC_PUSH, txn)


# name, setup8, data_len (0 = no data phase), dir_in, expect note
SHAPES = [
    # batch A - known/likely served sanity across wLength classes
    ("A1-desc-device18", bytes([0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00]), 0x12, True, "18B device desc signature ac052712"),
    ("A2-desc-string3-B6", bytes([0x80, 0x06, 0x03, 0x03, 0x09, 0x04, 0xB6, 0x00]), 0xB6, True, "CPID string"),
    ("A3-desc-string3-FF", bytes([0x80, 0x06, 0x03, 0x03, 0x09, 0x04, 0xFF, 0x00]), 0xFF, True, "CPID string, 255 ask"),
    ("A4-dfu-getstatus", bytes([0xA1, 0x03, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00]), 0x06, True, "6B DFU status (served day-one)"),
    # batch B - stall candidates, one per run
    ("B1-getstatus-40", bytes([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00]), 0x40, True, "feng-shui shape, complete"),
    ("B2-getstatus-80", bytes([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00]), 0x80, True, "feng-shui shape w80"),
    ("B3-getstatus-0", bytes([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 0, True, "zero-len, status-only"),
    ("B4-desc-string-EE", bytes([0x80, 0x06, 0xEE, 0x03, 0x09, 0x04, 0xFF, 0x00]), 0xFF, True, "unsupported string idx"),
    ("B5-desc-qualifier", bytes([0x80, 0x06, 0x00, 0x06, 0x00, 0x00, 0x0A, 0x00]), 0x0A, True, "device qualifier"),
    ("B6-getconfig", bytes([0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]), 0x01, True, "get configuration"),
    ("B7-desc-string-badlang", bytes([0x80, 0x06, 0x04, 0x03, 0x15, 0x04, 0xFF, 0x00]), 0xFF, True, "string idx4 bad LANGID"),
    ("B8-req-7f-40", bytes([0x80, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00]), 0x40, True, "bogus bRequest"),
    ("B9-dfu-getstate", bytes([0xA1, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]), 0x01, True, "DFU getstate 1B"),
    ("B10-dfu-clrstatus", bytes([0x21, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 0, False, "DFU clrstatus status-only"),
    ("B11-dfu-abort", bytes([0x21, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 0, False, "DFU abort status-only"),
    ("B12-dfu-dnload0", bytes([0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 0, False, "DFU zero dnload marker"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shape", required=True, help="shape index (0-based) or name")
    args = ap.parse_args()

    if args.shape.isdigit():
        i = int(args.shape)
    else:
        names = [s[0] for s in SHAPES]
        if args.shape not in names:
            print("unknown shape; valid: %s"
                  % ", ".join("%d:%s" % (j, n) for j, n in enumerate(names)))
            return 1
        i = names.index(args.shape)
    name, setup, dlen, din, note = SHAPES[i]

    fd = os.open("/dev/raw0", os.O_RDWR)
    st0 = state(fd)
    print("state0: slot=%d captured=%d pushed=%d free=%d deq_off=%d ep0raw=%d"
          % (st0["slot"], st0["captured"], st0["pushed"], st0["free"],
             st0["deq_off"], st0["ep0"]))
    if not st0["captured"]:
        print("NO CAPTURE - re-arm first")
        return 1

    h0, _ = ringdump(fd)
    print("ring0: enq=%d cyc=%d hwdeq=%d epst=%d"
          % (h0["enq"], h0["cyc"], h0["hwdeq"], h0["epst"]))
    if h0["epst"] != 1:
        print("EP0 NOT RUNNING (ringdump epst=%d) - dirty/unknown, refusing"
              % h0["epst"])
        return 2

    if dlen:
        rc = push(fd, setup, dlen, din, True, True)
    else:
        rc = push(fd, setup, 0, din, False, True)
    print("push %s rc=%r" % (name, rc))

    time.sleep(0.35)
    st1 = state(fd)
    h1, _ = ringdump(fd)
    print("state1: pushed=%d deq_off=%d ep0raw=%d" % (st1["pushed"], st1["deq_off"], st1["ep0"]))
    print("ring1: enq=%d cyc=%d hwdeq=%d->%d epst=%d"
          % (h1["enq"], h1["cyc"], h0["hwdeq"], h1["hwdeq"], h1["epst"]))

    # consumed = hwdeq moved; 2=halted 3=stopped from context probe
    cons = h1["hwdeq"] != h0["hwdeq"]
    halted = (h1["epst"] in (2, 3)) or not cons
    print("consumed=%s (deq %s->%s)" % (cons, h0["hwdeq"], h1["hwdeq"]))

    if din and dlen:
        stat, data = readback(fd)
        print("readback status=%d first64=%s" % (stat, data[:64].hex()))
        print("nonzero in first64: %d" % sum(1 for b in data[:64] if b))
        if b"\xac\x05\x27\x12" in data[:64]:
            print("SIGNATURE: device descriptor served")
        if b"CPID" in data:
            print("SIGNATURE: CPID string served")

    if halted:
        with open("/tmp/scout-HALT", "w") as f:
            f.write(name)
        print("HALT DETECTED after %s - STOP the ladder" % name)
        return 2
    print("DONE %s" % name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
