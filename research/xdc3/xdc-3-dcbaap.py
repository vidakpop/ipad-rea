#!/usr/bin/env python3
"""DCBAAP hunt: find where the chip's device-context pointer really lives.

Known: CRCR-pointer at OP+0x18 (command walk follows it); OP+0x14 is the only
front-panel RW byte found (0x40 sticks); OP+0x20 CONFIG is dead on this die.
Enable Slot still returns cc=9 (No Slots Available) - suspect the chip's
DCBAA pointer never received our array.
Sweep: fresh bringup, write the DCBAA address at candidate offset C,
set OP+0x14=0x40, run Enable Slot, look for cc=1.

Usage: sudo python3 tools/xdc-3-dcbaap.py <dma-base-hex>
"""
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from xdc import Xdc  # noqa: E402
from xdc3lib import bringup_v3, enable_slot_try  # noqa: E402

CANDIDATES = [0x14, 0x1C, 0x24, 0x2C, 0x30, 0x34, 0x38, 0x40, 0x44, 0x48]


def main():
    if len(sys.argv) < 2:
        print("usage: xdc-3-dcbaap.py <dma-base-hex>")
        return 1
    x = Xdc(dma=int(sys.argv[1], 16))
    print("OP=%d slots=%d ports=%d scratch=%d" %
          (x.OP, x.maxslots, x.maxports, x.scratch))
    x.arm_irq()

    for C in CANDIDATES:
        bringup_v3(x)
        x.wr(x.OP + 0x14, 0x40)          # CONFIG? MaxSlotsEn
        if C != 0x14:
            x.wr(x.OP + C, x.DMA + 0x46000)  # DCBAA candidate (low half)
        rb = {o: x.rd(x.OP + o) for o in
              [0x10, 0x14, 0x18, 0x1C, 0x20, C]}
        cc, slot = enable_slot_try(x, wait=3.0)
        print("[C=%#04x] rb=%s -> EnableSlot cc=%r slot=%r" %
              (C, {hex(o): hex(v) for o, v in rb.items()}, cc, slot))
        if cc == 1 and slot:
            print(">>> DCBAAP FOUND at OP+%#x (with 0x14=CONFIG): slot=%d" %
                  (C, slot))
            with open("/tmp/xdc-slot-id", "w") as f:
                f.write(str(slot))
            with open("/tmp/xdc-dcbaap-off", "w") as f:
                f.write(hex(C))
            return 0
        if cc is not None and cc != 9:
            print("    interesting: cc=%s at C=%#x" % (cc, C))
    print(">>> no candidate changed the outcome")
    return 1


if __name__ == "__main__":
    sys.exit(main())
