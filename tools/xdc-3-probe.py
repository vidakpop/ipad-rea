#!/usr/bin/env python3
"""Forensic probe: where does the xDC fetch command TRBs from, and what does it
consider malformed? Prints FULL command-completion events (param = address of
the command TRB the completion belongs to) plus CRCR readback after each step.

Matrix per run:
  TRB[0] at ring base (pool+0x42000):  No-Op (type 23), Enable Slot (type 9)
  pool+0x0 (DCBAA start):              Enable Slot (type 9), type 10 control
Usage: sudo python3 tools/xdc-3-probe.py <dma-base-hex>
"""
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from xdc import Xdc, TRB_TYPES  # noqa: E402


def show(ev):
    if ev is None:
        print("      event: none")
        return
    typ, cc, slot, param, status, control = ev
    print("      event: type=%d(%s) cc=%d slot=%d param=%#x status=%#x" %
          (typ, TRB_TYPES.get(typ, "?"), cc, slot, param, status))


def main():
    if len(sys.argv) < 2:
        print("usage: xdc-3-probe.py <dma-base-hex>")
        return 1
    x = Xdc(dma=int(sys.argv[1], 16))
    print("OP=%d slots=%d ports=%d scratch=%d DB=%#x RTS=%#x" %
          (x.OP, x.maxslots, x.maxports, x.scratch, x.DBOFF, x.RTS))
    x.arm_irq()
    x.bringup()
    print("[1] bringup ok")
    print("    CRCR readback: %#x" % x.r64(x.OP + 0x10))

    def step(label, addr, typ, cycle=1):
        print("[%s] %s @ %#x (pool+%#x)" % (label, label.split()[0], x.DMA + addr, addr))
        x.events_clear()
        x.memwr(addr, x.trb(0, 0, typ, cycle))
        x.doorbell(0)
        show(x.wait_event(timeout=2.0))
        print("    CRCR readback: %#x" % x.r64(x.OP + 0x10))

    step("No-Op 23 @ring", x.CMDR, 23)
    step("EnableSlot 9 @ring", x.CMDR, 9)
    step("EnableSlot 9 @pool0", 0x0, 9)
    step("CtrlType 10 @pool0", 0x0, 10)
    step("EnableSlot 9 @ring+10", x.CMDR + 0x10, 9)
    return 0


if __name__ == "__main__":
    sys.exit(main())
