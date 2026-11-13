#!/usr/bin/env python3
"""OP-region register map dump: find every RW/sticky register around the front.

Reads OP+0x00..0x40 and the interrupter area after a v3 bring-up, writes a
known probe value (0xA5A55A5A) into the same range with readback compare, and
prints the map. Sticky-bytes reveal the chip's true register file layout.

Usage: sudo python3 tools/xdc-3-regmap.py <dma-base-hex>
"""
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from xdc import Xdc  # noqa: E402
from xdc3lib import bringup_v3, enable_slot_try, wipe_events  # noqa: E402

PROBE = 0xA5A55A5A  # classic probe pattern


def main():
    if len(sys.argv) < 2:
        print("usage: xdc-3-regmap.py <dma-base-hex>")
        return 1
    x = Xdc(dma=int(sys.argv[1], 16))
    print("OP=%d slots=%d ports=%d scratch=%d RTS=%#x DB=%#x" %
          (x.OP, x.maxslots, x.maxports, x.scratch, x.RTS, x.DBOFF))
    x.arm_irq()
    bringup_v3(x)
    # run one Enable Slot so the allocator state is "engaged"
    cc, slot = enable_slot_try(x, wait=3.0)
    print("[1] EnableSlot probe: cc=%r slot=%r" % (cc, slot))

    print("[2] OP front-panel read map (fresh, post-bringup):")
    for off in range(0x00, 0x40, 4):
        print("    OP+%#04x = %#010x" % (off, x.rd(x.OP + off)))
    print("    RTS area:")
    for off in range(0x00, 0x40, 4):
        print("    RTS+%#04x = %#010x" % (off, x.rd(x.RTS + off)))

    print("[3] probe-writes with readback (masked bits show real registers):")
    for off in range(0x20, 0x40, 4):
        old = x.rd(x.OP + off)
        x.wr(x.OP + off, PROBE)
        new = x.rd(x.OP + off)
        x.wr(x.OP + off, old)  # restore
        stick = "%#010x" % new if new != old else "(volatile/RO->0)"
        flag = " <<< RW BITS: %#x" % (new & old | 0) if new != old else ""
        print("    OP+%#04x old=%#010x after-write=%s%s" % (off, old, stick, flag))

    # RTS area probes too (event ring regs live around RTS+0x20)
    for off in range(0x00, 0x40, 4):
        old = x.rd(x.RTS + off)
        x.wr(x.RTS + off, PROBE)
        new = x.rd(x.RTS + off)
        x.wr(x.RTS + off, old)
        stick = "%#010x" % new if new != old else "(RO)"
        print("    RTS+%#04x old=%#010x after=%s" % (off, old, stick))
    return 0


if __name__ == "__main__":
    sys.exit(main())
