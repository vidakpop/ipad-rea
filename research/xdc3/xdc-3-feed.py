#!/usr/bin/env python3
"""Probe #3: feed the chip at ITS OWN command-fetch address (pool+0x1fa0).

Forensics from probe #1/#2: CRCR pointer writes are inert on this xDC alias;
the chip deterministically fetches a command TRB from pool+0x1fa0 whenever the
command ring is made to run (CRCR CRR=1 write — the doorbell is inert for the
command ring). Zeros there completed as cc=5 (valid-per-cycle garbage, type 0
reserved), so the chip's internal RCS is 0: TRBs with cycle=0 should execute.

If Enable Slot completes cc=1 at the fixed pointer, M2 unlocks: subsequent
commands go at 0x1fb0 (walk mode), param fields give us the live pointer.

Usage: sudo python3 tools/xdc-3-feed.py <dma-base-hex>
"""
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from xdc import Xdc, TRB_TYPES  # noqa: E402

FETCH = 0x1FA0  # the chip's observed internal command-fetch offset in pool


def show(ev, tag):
    if ev is None:
        print("    %-24s event: none" % tag)
        return None
    typ, cc, slot, param, status, control = ev
    print("    %-24s event: type=%d(%s) cc=%d slot=%d param=%#x status=%#x" %
          (tag, typ, TRB_TYPES.get(typ, "?"), cc, slot, param, status))
    return ev


def main():
    if len(sys.argv) < 2:
        print("usage: xdc-3-feed.py <dma-base-hex>")
        return 1
    x = Xdc(dma=int(sys.argv[1], 16))
    print("OP=%d slots=%d ports=%d scratch=%d" %
          (x.OP, x.maxslots, x.maxports, x.scratch))
    x.arm_irq()
    x.bringup()
    print("[1] bringup ok")

    def kick():
        x.w64(x.OP + 0x10, (x.DMA + x.CMDR) | 8)  # CRR=1: the working trigger

    def attempt(off, typ, cycle, tag):
        x.events_clear()
        x.memwr(off, x.trb(0, 0, typ, cycle))
        kick()
        return show(x.wait_event(timeout=1.5), tag)

    ev = attempt(FETCH, 9, 0, "EnSlot9 cyc0 @1fa0")
    if not ev or ev[1] != 1:
        ev = attempt(FETCH, 23, 0, "NoOp23 cyc0 @1fa0")
    if not ev or ev[1] != 1:
        ev = attempt(FETCH, 9, 1, "EnSlot9 cyc1 @1fa0")
    if not ev or ev[1] != 1:
        ev = attempt(FETCH, 23, 1, "NoOp23 cyc1 @1fa0")
    if not ev or ev[1] != 1:
        print(">>> feed at 0x1fa0 did not execute")
        return 1

    slot = ev[2]
    print(">>> EXECUTION AT FIXED POINTER CONFIRMED")
    with open("/tmp/xdc-slot-id", "w") as f:
        f.write(str(slot))
    if ev[1] == 1 and ev[0] == 33 and slot > 0:
        print(">>> M2 UNLOCKED: slot=%d" % slot)
    # does the pointer advance? no-op at 0x1fb0
    attempt(FETCH + 0x10, 23, 0, "NoOp23 cyc0 @1fb0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
