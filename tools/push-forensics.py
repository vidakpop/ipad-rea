#!/usr/bin/env python3
"""raw0 push + forensics in one shot.

Usage:
  sudo python3 tools/push-forensics.py [--get-descriptor | --dangling]
       [--dump] [--readback N]

Pushes one control TD on the captured EP0 ring, then dumps ring state.
--dangling omits the status phase (incomplete control TD - the feng-shui
leak primitive shape).
"""
import argparse
import fcntl
import ctypes
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


def state(fd):
    rc = fcntl.ioctl(fd, IOC_STATE, bytes(bytearray(ST_SIZE)), False)
    f = struct.unpack("<QIIIIIIII", rc)
    return dict(xhci=f[0], slot=f[1], free=f[3], cyc=f[4],
                captured=f[5], pushed=f[6], deq_off=f[7])


def ringdump(fd, rows=slice(0, 8)):
    rc = fcntl.ioctl(fd, IOC_RINGDUMP, bytes(bytearray(RD_SIZE)), False)
    vals = struct.unpack("<%dI" % (RD_SIZE // 4), rc)
    head = dict(enq=vals[0], cyc=vals[1], hwdeq=vals[2], epst=vals[3],
                slot=vals[4])
    return head, vals


def pr_rows(vals, head, lo, hi):
    print("idx cyc type w0        w1        w2        w3")
    for i in range(lo, min(hi, NDUMP)):
        w0, w1, w2, w3 = vals[6 + i * 4: 6 + i * 4 + 4]
        print("%3d  %d   %2d  %08x  %08x  %08x  %08x %s"
              % (i, w3 & 1, (w3 >> 10) & 0x3f, w0, w1, w2, w3,
                 "ENQ" if i == head["enq"] else ""))


def push(fd, setup, data_len, dir_in, has_data, has_status, send_bytes=None):
    if send_bytes is not None:
        n = len(send_bytes)
        cdata = (ctypes.c_ubyte * (n or 1))()
        ctypes.memmove(cdata, send_bytes, n)
        ptr = ctypes.addressof(cdata)
        holder = cdata
    else:
        cdata = (ctypes.c_ubyte * 64)()
        ptr = ctypes.addressof(cdata)
        holder = cdata
    txn = struct.pack("<8sIBBBBQII",
                      setup, data_len, 1 if has_data else 0,
                      1 if has_status else 0,
                      1 if dir_in else 0, 0, ptr, 0, 0)
    # mutate path: use a mutable buffer to get the ioctl's int return
    buf = bytearray(txn)
    rc = fcntl.ioctl(fd, IOC_PUSH, bytes(buf))
    return rc, holder


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dangling", action="store_true",
                    help="omit the status phase")
    ap.add_argument("--out", type=str, default=None,
                    help="send a data phase OUT with these bytes")
    ap.add_argument("--dump", action="store_true")
    args = ap.parse_args()

    fd = os.open("/dev/raw0", os.O_RDWR)
    st = state(fd)
    print("before: slot=%d captured=%d cyc=%d pushed=%d deq_off=%d"
          % (st["slot"], st["captured"], st["cyc"], st["pushed"],
             st["deq_off"]))
    if not st["captured"]:
        print("NO CAPTURE - run the PCI cycle first")
        sys.exit(1)

    head, vals = ringdump(fd)
    before_enq = head["enq"]
    print("ring: enq=%d cyc=%d ep_state=%d" % (head["enq"], head["cyc"],
                                               head["epst"]))
    if args.dump:
        pr_rows(vals, head, max(0, head["enq"] - 8), head["enq"] + 4)

    # GET_DESCRIPTOR device, wLength 18 (the transaction the ROM serves
    # happily; same shape as the first confirmed wire execution)
    setup = bytes([0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00])
    t0 = time.time()
    rc, holder = push(fd, setup,
                      18,
                      (args.out is None),
                      has_data=True,
                      has_status=not args.dangling,
                      send_bytes=args.out.encode() if args.out else None)
    print("push rc=%r after %.1fms" % (rc, (time.time() - t0) * 1000))

    time.sleep(0.3)
    head2, vals2 = ringdump(fd)
    print("after: enq=%d->%d moved=%d ep_state=%d"
          % (before_enq, head2["enq"], head2["enq"] - before_enq,
             head2["epst"]))
    if args.dump:
        pr_rows(vals2, head2, max(0, head2["enq"] - 8), head2["enq"] + 4)


if __name__ == "__main__":
    main()
