#!/usr/bin/env python3
"""Rung-2 truth matrix: which second command executes after EnableSlot?

V1 No-Op (23)      - flow truth: any second command at all?
V2 EnSlot (9) + param=ICTX + BSR + slot - do my extra bits poison a good type?
V3 AddrDev (11) minimal (param=0, no BSR, slot=1)
V4 AddrDev (11) full (BSR, slot=1, param=ICTX)
Each variant: fresh bringup -> EnableSlot -> lay variant at pool+0x0 ->
stop(cc24) -> restart -> doorbell -> await any event at the fetch spot.

Usage: sudo python3 tools/xdc-3-rung2.py <dma-base-hex>
"""
import struct
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from xdc import Xdc  # noqa: E402
from xdc3lib import (bringup_v3, scan_events, wipe_events,  # noqa: E402
                    LADDER)

ICTX = 0x45000


def await_fetch(x, timeout=4.0, tag=""):
    t0 = time.time()
    seen = set()
    while time.time() - t0 < timeout:
        for ev in scan_events(x):
            key = (ev[0], ev[4], ev[5], ev[6])
            if key in seen:
                continue
            seen.add(key)
            if ev[1] == 33 and ev[4] in (x.DMA + LADDER, x.DMA + LADDER + 16):
                print("    %-6s cc=%d slot=%d param=%#x (fetched!)" %
                      (tag, ev[2], ev[3], ev[4]))
                return ev
            if ev[1] == 33 and ev[2] == 24:
                print("    %-6s stop-event param=%#x (filtered)" %
                      (tag, ev[4]))
        time.sleep(0.05)
    print("    %-6s NOTHING" % tag)
    return None


def stop_cycle(x):
    for attempt in range(4):
        wipe_events(x)
        x.w64(x.OP + 0x18, 2)
        t0 = time.time()
        ok = False
        while time.time() - t0 < 1.0:
            for ev in scan_events(x):
                if ev[1] == 33 and ev[2] == 24:
                    ok = True
                    break
            if ok:
                break
            time.sleep(0.02)
        if ok:
            x.w64(x.OP + 0x18, (x.DMA + LADDER) | 8)
            time.sleep(0.05)
            x.doorbell(0)
            return True
        time.sleep(0.2)
    print("    stop event never came")
    x.w64(x.OP + 0x18, (x.DMA + LADDER) | 8)
    x.doorbell(0)
    return False


def main():
    if len(sys.argv) < 2:
        print("usage: xdc-3-rung2.py <dma-base-hex>")
        return 1
    x = Xdc(dma=int(sys.argv[1], 16))
    print("OP=%d slots=%d ports=%d scratch=%d" %
          (x.OP, x.maxslots, x.maxports, x.scratch))
    x.arm_irq()

    variants = [
        ("V1-NoOp", x.trb(0, 0, 23, 0)),
        ("V2-EnSlot-extra", x.trb(x.DMA + ICTX, 0, 9, 0, ctl_bits=1 << 9, slot=1)),
        ("V3-Addr-min", x.trb(0, 0, 11, 0, slot=1)),
        ("V4-Addr-full", x.trb(x.DMA + ICTX, 0, 11, 0, ctl_bits=1 << 9, slot=1)),
    ]

    for tag, trb in variants:
        print("== %s ==" % tag)
        bringup_v3(x)
        x.wr(x.OP + 0x38, 0xFF)
        # quick port check (no reset needed for command-only tests)
        x.memwr(LADDER, x.trb(0, 0, 9, 0))
        wipe_events(x)
        x.doorbell(0)
        t0 = time.time()
        slot = None
        seen = set()
        while time.time() - t0 < 4:
            for ev in scan_events(x):
                key = (ev[0], ev[4], ev[5], ev[6])
                if key in seen:
                    continue
                seen.add(key)
                if ev[1] == 33 and ev[2] == 1 and ev[3] >= 1:
                    slot = ev[3]
                    break
            if slot:
                break
            time.sleep(0.05)
        if not slot:
            print("    EnableSlot failed; skip variant")
            continue
        print("    EnableSlot ok slot=%d" % slot)
        x.memwr(LADDER, trb)
        wipe_events(x)
        stop_cycle(x)
        await_fetch(x, tag=tag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
