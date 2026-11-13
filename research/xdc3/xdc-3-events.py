#!/usr/bin/env python3
"""Decode the ENTIRE event ring, not just the first 4 slots.

xdc.py wait_event() only scans EVTR[0..3] (64 bytes). The pool dump showed
chip-written content at EVTR+0x40 .. EVTR+0xfd0: real events were landing
outside the scan window. This script replays a bringup + a real No-Op +
Enable Slot at the ring base and then decodes every TRB of the whole 4K
event page, printing type/cc/slot/param for anything with the cycle bit set.

Usage: sudo python3 tools/xdc-3-events.py <dma-base-hex>
"""
import struct
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from xdc import Xdc, TRB_TYPES  # noqa: E402

EVENT_TYPES = {
    32: "TRANSFER", 33: "CMD_COMPLETION", 34: "PORT_STATUS", 36: "STREAM",
    37: "MFWR", 39: "MFINDEX_WRAP", 35: "BANDWIDTH", 38: "DOORBELL",
}


def decode(x, verbose=True):
    print("== full event ring decode (256 TRBs) ==")
    found = 0
    for k in range(256):
        off = x.EVTR + 16 * k
        data = x.memck(off, 16)
        if not any(data):
            continue
        param, status, control = struct.unpack("<QII", data)
        if not (control & 1):
            # present but not ours (cycle 0): still show for forensics
            if verbose:
                print("  [%3d +%#06x] (cyc0) param=%#x cc=%d ctl=%#x" %
                      (k, off, param, (status >> 24) & 0xFF, control))
            continue
        typ = (control >> 10) & 0x3F
        cc = (status >> 24) & 0xFF
        slot = (control >> 24) & 0xFF
        print("  [%3d +%#06x] type=%2d %-13s cc=%2d slot=%2d param=%#x status=%#x" %
              (k, off, typ, EVENT_TYPES.get(typ, "?"), cc, slot, param, status))
        found += 1
    print("== %d live (cycle=1) events ==" % found)
    return found


def main():
    if len(sys.argv) < 2:
        print("usage: xdc-3-events.py <dma-base-hex>")
        return 1
    x = Xdc(dma=int(sys.argv[1], 16))
    print("OP=%d slots=%d ports=%d scratch=%d" %
          (x.OP, x.maxslots, x.maxports, x.scratch))
    x.arm_irq()
    x.bringup()
    print("[1] bringup ok; fresh clean of event page, then No-Op + Enable Slot")
    # zero the whole event page and park ERDP at base
    x.memwr(x.EVTR, b"\x00" * 0x1000)
    x.w64(x.RTS + 0x20 + 0x18, x.DMA + x.EVTR)

    x.memwr(x.CMDR, x.trb(0, 0, 23, 1))  # No-Op command
    x.doorbell(0)
    time.sleep(0.5)
    x.memwr(x.CMDR, x.trb(0, 0, 9, 1))  # Enable Slot
    x.doorbell(0)
    time.sleep(0.5)
    n = decode(x)
    if n == 0:
        print("[2] nothing new; try No-Op twice more with CRR kick")
        x.w64(x.OP + 0x10, (x.DMA + x.CMDR) | 8)
        x.memwr(x.CMDR, x.trb(0, 0, 23, 1))
        x.doorbell(0)
        time.sleep(0.5)
        decode(x)
    return 0


if __name__ == "__main__":
    sys.exit(main())
