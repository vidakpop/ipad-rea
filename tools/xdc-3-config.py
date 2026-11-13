#!/usr/bin/env python3
"""CONFIG hunt: find where this xDC alias actually reads MaxSlotsEn from.

State: bringup v3 (swapped DCBAAP/CRCR) makes the chip execute our Enable Slot
TRB, but it completes cc=9 (No Slots Available) - the chip's MaxSlotsEn stays
0, so our write to OP+0x20 did not land in its CONFIG.
Sweep candidate offsets with a fresh bring-up each, run Enable Slot, report.

Usage: sudo python3 tools/xdc-3-config.py <dma-base-hex>
"""
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from xdc import Xdc  # noqa: E402
from xdc3lib import (bringup_v3_cfg, enable_slot_try,  # noqa: E402
                     LADDER, DCBAA_V2)

CANDIDATES = [0x20, 0x1C, 0x24, 0x28, 0x2C, 0x14]


def main():
    if len(sys.argv) < 2:
        print("usage: xdc-3-config.py <dma-base-hex>")
        return 1
    x = Xdc(dma=int(sys.argv[1], 16))
    print("OP=%d slots=%d ports=%d scratch=%d" %
          (x.OP, x.maxslots, x.maxports, x.scratch))
    x.arm_irq()
    val = x.maxslots | (min(x.scratch, 0x1F) << 25)

    for C in CANDIDATES:
        bringup_v3_cfg(x, val, C)
        rb = {o: x.rd(x.OP + o) for o in [0x08, 0x14, 0x1C, 0x20, 0x24, 0x28, 0x2C]}
        cc, slot = enable_slot_try(x)
        print("[C=%#04x] rb %s ->.EnableSlot cc=%r slot=%r" %
              (C, {hex(o): hex(v) for o, v in rb.items()}, cc, slot))
        if cc == 1 and slot:
            print(">>> CONFIG FOUND at OP+%#x: slot=%d" % (C, slot))
            with open("/tmp/xdc-slot-id", "w") as f:
                f.write(str(slot))
            with open("/tmp/xdc-config-off", "w") as f:
                f.write(hex(C))
            return 0
        if cc is not None and cc != 9:
            print("    interesting: completion changed (cc=%s)" % cc)
    print(">>> no candidate unlocked slots")
    return 1


if __name__ == "__main__":
    sys.exit(main())
