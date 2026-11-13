#!/usr/bin/env python3
"""SPEAK3: ride the walk - lay each command ahead of the prefetch executor.

Grand unified model of this AMD xDC alias:
 - a walk pointer starts at the value written to OP+0x18 at bring-up and
   consumes 16-byte "TRBs" continuously (~8 ms/TRB), executing valid command
   TRBs (real completions) and garbage (cc=5 storm events) alike;
 - doorbells/CRR writes are inert;
 - later commands must be laid AHEAD of the walk position (latest storm
   event param + margin).
Sequence: EnableSlot (at base) -> track walk -> AddressDevice BSR=1 ->
GET_DESCRIPTOR at address 0.

Usage: sudo python3 tools/xdc-3-speak3.py <dma-base-hex>
"""
import struct
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from xdc import Xdc  # noqa: E402
from xdc3lib import bringup_v3, scan_events, wipe_events, LADDER  # noqa: E402

ICTX = 0x45000
OCTX = 0x48000
EPRING = 0x30000
DATA = 0x50000


def latest_storm(x):
    """Newest cc=5 event param = current walk position."""
    best = None
    for ev in scan_events(x):
        if ev[2] == 5:
            p = ev[4]
            if best is None or p > best:
                best = p
    return best


def await_real(x, timeout=6.0, tag=""):
    """Wait for a completion event with cc not in (5, 24)."""
    t0 = time.time()
    seen = set()
    while time.time() - t0 < timeout:
        for ev in scan_events(x):
            key = (ev[0], ev[4], ev[5], ev[6])
            if key in seen:
                continue
            seen.add(key)
            if ev[1] == 33 and ev[2] in (1, 2, 4, 6, 7, 8, 9, 11, 12, 13, 19, 22):
                print("    %-10s cc=%d slot=%d param=%#x" %
                      (tag, ev[2], ev[3], ev[4]))
                return ev
        time.sleep(0.05)
    print("    %-10s NO COMPLETION" % tag)
    return None


def walk_pos_with_margin(x, margin=0x100):
    """Sample the walk twice to extrapolate live position + margin."""
    p1 = latest_storm(x)
    t1 = time.time()
    time.sleep(0.3)
    p2 = latest_storm(x)
    t2 = time.time()
    if p1 is None:
        # no storm visible (events wiped); assume base + elapsed margin
        print("    (no storm visible; using static margin)")
        return LADDER + 0x400
    rate = (p2 - p1) / (t2 - t1) if p2 and p2 > p1 else 1600.0
    pos = p2 + int(rate * (time.time() - t2)) + margin
    print("    walk %x->%x rate=%d B/s; lay at +%#x" % (p1, p2, rate, pos))
    return pos & 0xFFF_FFFF


def main():
    if len(sys.argv) < 2:
        print("usage: xdc-3-speak3.py <dma-base-hex>")
        return 1
    x = Xdc(dma=int(sys.argv[1], 16))
    print("OP=%d slots=%d ports=%d scratch=%d" %
          (x.OP, x.maxslots, x.maxports, x.scratch))
    x.arm_irq()
    bringup_v3(x)
    x.wr(x.OP + 0x38, 0xFF)
    print("[1] bringup ok (walk started at pool+0)")

    # port reset
    ps = x.portsc(2)
    x.wr(x.OP + 0x400 + 0x10, ps | 0x10)
    t0 = time.time()
    while time.time() - t0 < 3:
        cur = x.portsc(2)
        if not ((cur >> 4) & 1) and ((cur >> 5) & 0xF) == 0 and (cur & 1):
            break
        time.sleep(0.01)
    print("[2] port 2: SPD=%d" % ((x.portsc(2) >> 10) & 0xF))

    # contexts
    x.memwr(0x46000 + 8, struct.pack("<Q", x.DMA + OCTX))
    x.memwr(OCTX, b"\x00" * 0x1000)
    x.memwr(ICTX, b"\x00" * 0x60)
    slot_dw0 = 0x08000000 | (3 << 20)
    slot_dw1 = (2 << 16)
    x.memwr(ICTX + 0x00, struct.pack("<I", 0x3))
    x.memwr(ICTX + 0x20, struct.pack("<7I", slot_dw0, slot_dw1, 0, 0, 0, 0, 0))
    ep0_dw1 = (64 << 16) | (4 << 3) | (3 << 1)
    ep0_deq = (x.DMA + EPRING) | 1
    x.memwr(ICTX + 0x40, struct.pack("<6I", 0, ep0_dw1,
                                     ep0_deq & 0xFFFFFFFF, ep0_deq >> 32, 8, 0))
    x.memwr(EPRING, b"\x00" * 0x1000)

    # rung 1: EnableSlot at the walk base
    x.memwr(LADDER, x.trb(0, 0, 9, 0))
    wipe_events(x)
    print("[3] EnableSlot at +0x0")
    ev = await_real(x, tag="EnSlot")
    if ev is None or ev[2] != 1 or ev[3] < 1:
        return 1
    slot = ev[3]

    # rung 2: lay AddressDevice ahead of the walk
    pos = walk_pos_with_margin(x)
    bsr = 1 << 9
    x.memwr(pos, x.trb(x.DMA + ICTX, 0, 11, 0, ctl_bits=bsr, slot=slot))
    print("[4] AddressDevice BSR=1 slot=%d laid at +%#x" % (slot, pos))
    ev = await_real(x, tag="AddrDev")
    if ev is None:
        return 1
    if ev[2] != 1:
        print("    AddressDevice FAILED cc=%d" % ev[2])
        return 1
    out = x.memck(OCTX, 64)
    d = struct.unpack("<16I", out)
    print("    output ctx: %s" % " ".join("%08x" % v for v in d[:8]))
    print(">>> SLOT %d ADDRESSED AT ADDRESS 0 (BSR=1)" % slot)

    # rung 3: GET_DESCRIPTOR on the EP0 ring, doorbell the slot
    print("[5] GET_DESCRIPTOR @ address 0")
    setup = bytes([0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00])
    x.memwr(EPRING, struct.pack("<Q", int.from_bytes(setup, "little")) +
            struct.pack("<II", (2 << 16), (1) | (2 << 10) | (1 << 6)))
    x.memwr(EPRING + 16, struct.pack("<QII", x.DMA + DATA, 0x40,
            (1) | (3 << 10) | (1 << 16) | (1 << 5)))
    x.memwr(EPRING + 32, struct.pack("<QII", 0, 0, (1) | (4 << 10) | (1 << 5)))
    wipe_events(x)
    x.doorbell(slot, 1)
    t0 = time.time()
    found = None
    seen = set()
    while time.time() - t0 < 6.0 and not found:
        for ev in scan_events(x):
            key = (ev[0], ev[4], ev[5], ev[6])
            if key in seen:
                continue
            seen.add(key)
            print("    ev: type=%d cc=%d slot=%d ep=%d param=%#x status=%#x" %
                  (ev[1], ev[2], ev[3], (ev[6] >> 16) & 0x1F, ev[4], ev[5]))
            if ev[1] == 32:
                found = ev
                break
        time.sleep(0.05)
    if not found:
        print("    no transfer event")
        return 1
    got = x.memck(DATA, 0x40)
    print("    descriptor: %s" % got[:18].hex())
    vend = struct.unpack_from("<H", got, 8)[0] if len(got) >= 10 else 0
    if vend == 0x05AC:
        print(">>> THE A5 ANSWERED AT ADDRESS 0 - THE WALL IS DOWN")
        return 0
    print(">>> transfer completed; descriptor check: %#x" % vend)
    return 0


if __name__ == "__main__":
    sys.exit(main())
