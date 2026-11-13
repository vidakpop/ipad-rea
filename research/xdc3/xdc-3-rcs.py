#!/usr/bin/env python3
"""Probe #2: RCS (Ring Cycle State) hypothesis.

bringup() programs CRCR as pointer-only (bit0/RCS=0) while every TRB we write
carries cycle=1. Under the xHCI ownership protocol the ring must SKIP cycle-1
TRBs when RCS=0, which would explain: no events at the ring, phantom TRB-error
completions from zero garbage (cycle 0 == RCS 0 -> "valid" type-0 reserved TRB).

This probe rewrites CRCR with RCS=1 (and a CRR=1 variant) and retests a real
No-Op (type 23) and Enable Slot (type 9) at the ring base.

Usage: sudo python3 tools/xdc-3-rcs.py <dma-base-hex>
"""
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from xdc import Xdc, TRB_TYPES  # noqa: E402


def show(ev, tag):
    if ev is None:
        print("    %-22s event: none" % tag)
        return None
    typ, cc, slot, param, status, control = ev
    print("    %-22s event: type=%d(%s) cc=%d slot=%d param=%#x" %
          (tag, typ, TRB_TYPES.get(typ, "?"), cc, slot, param))
    return ev


def main():
    if len(sys.argv) < 2:
        print("usage: xdc-3-rcs.py <dma-base-hex>")
        return 1
    x = Xdc(dma=int(sys.argv[1], 16))
    print("OP=%d slots=%d ports=%d scratch=%d DB=%#x RTS=%#x" %
          (x.OP, x.maxslots, x.maxports, x.scratch, x.DBOFF, x.RTS))
    x.arm_irq()
    x.bringup()
    print("[1] bringup ok (CRCR pointer-only, RCS=0)")

    # variant 1: RCS=1 (cycle state high) — cycle-1 TRBs become valid
    x.w64(x.OP + 0x10, (x.DMA + x.CMDR) | 1)
    x.events_clear()
    x.memwr(x.CMDR, x.trb(0, 0, 23, 1))  # real No-Op command
    x.doorbell(0)
    ev = x.wait_event(timeout=2.0)
    show(ev, "NoOp23 RCS=1 @ring")

    x.events_clear()
    x.memwr(x.CMDR, x.trb(0, 0, 9, 1))  # Enable Slot
    x.doorbell(0)
    ev = x.wait_event(timeout=2.0)
    if show(ev, "EnSlot9 RCS=1 @ring"):
        typ, cc, slot = ev[0], ev[1], ev[2]
        if cc == 1:
            print(">>> M2 UNLOCKED on RCS=1: slot=%d" % slot)
            with open("/tmp/xdc-slot-id", "w") as f:
                f.write(str(slot))
            return 0

    # variant 2: CRR=1 (ring starts immediately at write)
    x.w64(x.OP + 0x10, (x.DMA + x.CMDR) | 8)
    x.events_clear()
    x.memwr(x.CMDR, x.trb(0, 0, 23, 1))
    x.doorbell(0)
    show(x.wait_event(timeout=2.0), "NoOp23 CRR=1 @ring")

    # variant 3: RCS=1 AND CRR=1
    x.w64(x.OP + 0x10, (x.DMA + x.CMDR) | 9)
    x.events_clear()
    x.memwr(x.CMDR, x.trb(0, 0, 23, 1))
    x.doorbell(0)
    show(x.wait_event(timeout=2.0), "NoOp23 RCS|CRR @ring")
    x.events_clear()
    x.memwr(x.CMDR, x.trb(0, 0, 9, 1))
    x.doorbell(0)
    ev = x.wait_event(timeout=2.0)
    if show(ev, "EnSlot9 RCS|CRR @ring"):
        typ, cc, slot = ev[0], ev[1], ev[2]
        if cc == 1:
            print(">>> M2 UNLOCKED on RCS|CRR: slot=%d" % slot)
            with open("/tmp/xdc-slot-id", "w") as f:
                f.write(str(slot))
            return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
