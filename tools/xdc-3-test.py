#!/usr/bin/env python3
"""M2 gate on xDC #3 (04:00.3): bringup, port reset, ENABLE_SLOT raw TRB.

The laptop-native raw-token path: with xdcdrv owning 04:00.3 there is no kernel
USB stack on the jack, so no enumeration-time SET_ADDRESS ever reaches the A5
DFU heap (the authors' wall, build/src/*/README.md section 1). If ENABLE_SLOT
completes with cc=1, the command ring executes on this thumb and the full
checkm8 flow can be ported as raw TRBs (never issuing SET_ADDRESS, working at
address 0 exactly like the Arduino sketch).

Usage: sudo python3 tools/xdc-3-test.py <dma-base-hex>
"""
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from xdc import Xdc, TRB_TYPES  # noqa: E402


def main():
    if len(sys.argv) < 2:
        print("usage: xdc-3-test.py <dma-base-hex>")
        return 1
    x = Xdc(dma=int(sys.argv[1], 16))
    print("OP=%d slots=%d ports=%d scratch=%d DB=%#x RTS=%#x" %
          (x.OP, x.maxslots, x.maxports, x.scratch, x.DBOFF, x.RTS))
    x.arm_irq()
    x.bringup()
    print("[1] bringup ok, controller running")

    # drain any stale events, then run the bringup NOP through the ring
    x.events_clear()
    x.doorbell(0)
    ev = x.wait_event(timeout=2.0)
    if ev:
        typ, cc, slot = ev[0], ev[1], ev[2]
        print("[2] NOP drain: type=%d(%s) cc=%d" % (typ, TRB_TYPES.get(typ, "?"), cc))
    else:
        print("[2] NOP drain: no event (frozen-pointer variant)")
    x.events_clear()

    # port scan: the iPad sits on root port 2 of this thumb
    live = []
    for p in range(1, x.maxports + 1):
        ps = x.portsc(p)
        ccs, pls, spd = ps & 1, (ps >> 5) & 0xF, (ps >> 10) & 0xF
        print("    port %d: CCS=%d PLS=%d SPD=%d" % (p, ccs, pls, spd))
        if ccs:
            live.append((p, spd))

    if 2 not in [p for p, _ in live]:
        print("ERROR: no device on port 2 (iPad). live=%r" % (live,))
        return 1

    # bus reset on port 2: the A5 DFU re-connects at address 0
    p = 2
    x.wr(x.OP + 0x400 + 0x10 * (p - 1), x.portsc(p) | 0x10)  # PR=1
    t0 = time.time()
    ps = None
    while time.time() - t0 < 3.0:
        cur = x.portsc(p)
        if not ((cur >> 4) & 1) and ((cur >> 5) & 0xF) == 0 and (cur & 1):
            ps = cur
            break
        time.sleep(0.01)
    if ps is None:
        ps = x.portsc(p)
        print("ERROR: port 2 reset did not settle: CCS=%d PLS=%d" %
              (ps & 1, (ps >> 5) & 0xF))
        return 1
    spd = (ps >> 10) & 0xF
    print("[3] port 2 reset done: CCS=1 PLS=0 SPD=%d" % spd)

    # drop the port-status changes queued by the reset
    x.events_clear()

    # ENABLE_SLOT at TRB[0]: frozen pointer means the chip executes ring base
    x.memwr(x.CMDR, x.trb(0, 0, 9, 1))
    x.doorbell(0)
    ev = x.wait_event(timeout=3.0)
    if ev is None:
        print("[4] ENABLE_SLOT: NO EVENT (command ring not executing)")
        return 1
    typ, cc, slot = ev[0], ev[1], ev[2]
    print("[4] ENABLE_SLOT: type=%d(%s) cc=%d slot=%d" %
          (typ, TRB_TYPES.get(typ, "?"), cc, slot))
    if cc == 1:
        print(">>> M2 UNLOCKED: command ring executes on 04:00.3")
        with open("/tmp/xdc-slot-id", "w") as f:
            f.write(str(slot))
        return 0
    print(">>> still blocked (cc=%d)" % cc)
    return 1


if __name__ == "__main__":
    sys.exit(main())
