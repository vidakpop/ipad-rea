#!/usr/bin/env python3
"""MaxSlotsEn blast: write 0xFF at every candidate front offset, per cell a
fresh bring-up, then Enable Slot; print any completion-code deviation.

Usage: sudo python3 tools/xdc-3-blast.py <dma-base-hex>
"""
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from xdc import Xdc  # noqa: E402
from xdc3lib import bringup_v3, enable_slot_try  # noqa: E402

SKIP = {0x00, 0x04, 0x08, 0x10, 0x18}


def main():
    if len(sys.argv) < 2:
        print("usage: xdc-3-blast.py <dma-base-hex>")
        return 1
    x = Xdc(dma=int(sys.argv[1], 16))
    print("OP=%d slots=%d ports=%d scratch=%d" %
          (x.OP, x.maxslots, x.maxports, x.scratch))
    x.arm_irq()
    offsets = [o for o in range(0x0C, 0xA4, 4) if o not in SKIP]
    for O in offsets:
        bringup_v3(x)
        x.wr(x.OP + O, 0xFF)
        cc, slot = enable_slot_try(x, wait=2.5)
        print("[O=%#04x] cc=%r slot=%r" % (O, cc, slot))
        if cc == 1 and slot:
            print(">>> HIT at OP+%#x: slot=%d" % (O, slot))
            with open("/tmp/xdc-slot-id", "w") as f:
                f.write(str(slot))
            with open("/tmp/xdc-config-hit", "w") as f:
                f.write(hex(O))
            return 0
        if cc not in (9, None):
            print("    DEVIATION at OP+%#x: cc=%r" % (O, cc))
    print(">>> blast complete; nothing unlocked")
    return 1


if __name__ == "__main__":
    sys.exit(main())
