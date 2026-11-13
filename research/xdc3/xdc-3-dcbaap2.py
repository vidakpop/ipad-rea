#!/usr/bin/env python3
"""DCBAAP hunt round 2: full-width pointer writes + CONFIG value sweep.

Round 1 facts: OP+0x30/34 echo 64-bit RW values (dead as DCBAAP), OP+0x14 is a
sticky RW byte, CRCR-pointer confirmed at OP+0x18, config@0x20 dead.
Round 2: w64 pointer writes at every untested qword slot, and if that fails,
sweep working values at OP+0x14.

Usage: sudo python3 tools/xdc-3-dcbaap2.py <dma-base-hex>
"""
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from xdc import Xdc  # noqa: E402
from xdc3lib import bringup_v3, enable_slot_try  # noqa: E402

QWORDS = [0x0C, 0x1C, 0x30, 0x50, 0x54, 0x58, 0x60, 0x68]
CONFIG_VALUES = [0x00, 0x01, 0x02, 0x08, 0x10, 0x20, 0x40, 0x7F, 0xFF]


def main():
    if len(sys.argv) < 2:
        print("usage: xdc-3-dcbaap2.py <dma-base-hex>")
        return 1
    x = Xdc(dma=int(sys.argv[1], 16))
    print("OP=%d slots=%d ports=%d scratch=%d" %
          (x.OP, x.maxslots, x.maxports, x.scratch))
    x.arm_irq()

    print("== sweep A: 64-bit DCBAA pointer candidates ==")
    for C in QWORDS:
        bringup_v3(x)
        x.wr(x.OP + 0x14, 0x40)
        x.w64(x.OP + C, x.DMA + 0x46000)
        cc, slot = enable_slot_try(x, wait=3.0)
        rb = x.rd(x.OP + C)
        print("[Q=%#04x] rb=%#010x -> cc=%r slot=%r" % (C, rb, cc, slot))
        if cc == 1 and slot:
            print(">>> DCBAAP at OP+%#x, slot=%d" % (C, slot))
            with open("/tmp/xdc-slot-id", "w") as f:
                f.write(str(slot))
            with open("/tmp/xdc-dcbaap-off", "w") as f:
                f.write(hex(C))
            return 0

    print("== sweep B: CONFIG value semantics at OP+0x14 ==")
    for V in CONFIG_VALUES:
        bringup_v3(x)
        x.wr(x.OP + 0x14, V)
        cc, slot = enable_slot_try(x, wait=3.0)
        rb = x.rd(x.OP + 0x14)
        print("[V=%#04x] rb=%#010x -> cc=%r slot=%r" % (V, rb, cc, slot))
        if cc == 1 and slot:
            print(">>> CONFIG value %#x unlocks slots: slot=%d" % (V, slot))
            with open("/tmp/xdc-slot-id", "w") as f:
                f.write(str(slot))
            with open("/tmp/xdc-config-val", "w") as f:
                f.write(hex(V))
            return 0
    print(">>> nothing unlocked slots")
    return 1


if __name__ == "__main__":
    sys.exit(main())
