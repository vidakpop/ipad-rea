#!/usr/bin/env python3
"""SPEAK2: per-command ring restart protocol.

Discovery: the command ring HALTS after each completion (doorbell #2 with the
same target is inert - duplicate suppression - and the event never lands).
Per-command protocol: rewrite the CRCR pointer (OP+0x18, swapped on this die)
with the next TRB's address | CRR(3-bit... bit3), then doorbell(0).
Sequence: EnableSlot -> AddressDevice(BSR=1) -> GET_DESCRIPTOR at address 0.

Usage: sudo python3 tools/xdc-3-speak2.py <dma-base-hex>
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


def crst(x, trb_off):
    """Stop the command ring (CS bit), then restart at trb_off + CRR, doorbell."""
    x.w64(x.OP + 0x18, 2)  # Command Stop (any pointer; CS bit set)
    for _ in range(20):     # wait for halt
        if not (x.rd(x.OP + 0x18) & 8):
            break
        time.sleep(0.01)
    x.w64(x.OP + 0x18, (x.DMA + trb_off) | 8)  # pointer | CRR -> restart at trb
    x.doorbell(0)


def await_completion(x, timeout=4.0, tag=""):
    t0 = time.time()
    seen = set()
    while time.time() - t0 < timeout:
        for ev in scan_events(x):
            key = (ev[4], ev[5], ev[6])
            if key in seen:
                continue
            seen.add(key)
            if ev[1] == 33 and ev[2] not in (5, 24):   # skip storm + ring-stopped
                print("    %-12s cc=%d slot=%d param=%#x" %
                      (tag, ev[2], ev[3], ev[4]))
                return ev
        time.sleep(0.05)
    print("    %-12s NO COMPLETION" % tag)
    return None


def main():
    if len(sys.argv) < 2:
        print("usage: xdc-3-speak2.py <dma-base-hex>")
        return 1
    x = Xdc(dma=int(sys.argv[1], 16))
    print("OP=%d slots=%d ports=%d scratch=%d" %
          (x.OP, x.maxslots, x.maxports, x.scratch))
    x.arm_irq()
    bringup_v3(x)
    print("[1] bringup ok; CRCR-status=%#x" % x.rd(x.OP + 0x18))
    x.wr(x.OP + 0x38, 0xFF)  # slot allocator gate

    # port reset
    ps = x.portsc(2)
    x.wr(x.OP + 0x400 + 0x10, ps | 0x10)
    t0 = time.time()
    while time.time() - t0 < 3:
        cur = x.portsc(2)
        if not ((cur >> 4) & 1) and ((cur >> 5) & 0xF) == 0 and (cur & 1):
            break
        time.sleep(0.01)
    print("[2] port 2 reset: SPD=%d" % ((x.portsc(2) >> 10) & 0xF))

    # contexts
    x.memwr(0x46000 + 8, struct.pack("<Q", x.DMA + OCTX))
    x.memwr(OCTX, b"\x00" * 0x1000)
    x.memwr(ICTX, b"\x00" * 0x60)
    slot_dw0 = 0x08000000 | (3 << 20)          # LAST_CTX(1) | HS
    slot_dw1 = (2 << 16)                       # ROOT_HUB_PORT(2)
    x.memwr(ICTX + 0x00, struct.pack("<I", 0x3))
    x.memwr(ICTX + 0x20, struct.pack("<7I", slot_dw0, slot_dw1, 0, 0, 0, 0, 0))
    ep0_dw1 = (64 << 16) | (4 << 3) | (3 << 1)
    ep0_deq = (x.DMA + EPRING) | 1
    x.memwr(ICTX + 0x40, struct.pack("<6I", 0, ep0_dw1,
                                     ep0_deq & 0xFFFFFFFF, ep0_deq >> 32, 8, 0))
    x.memwr(EPRING, b"\x00" * 0x1000)

    # rung 1: Enable Slot at TRB[0]
    x.memwr(LADDER, x.trb(0, 0, 9, 0))
    wipe_events(x)
    print("[3] EnableSlot")
    crst(x, LADDER)
    ev = await_completion(x, tag="EnSlot")
    if ev is None or ev[2] != 1 or ev[3] < 1:
        return 1
    slot = ev[3]
    print("    CRCR-status after: %#x" % x.rd(x.OP + 0x18))

    # rung 2: Address Device (BSR=1) back at the proven fetch spot pool+0x0,
    # with a varied doorbell target to avoid same-value suppression.
    bsr = 1 << 9
    x.memwr(LADDER, x.trb(x.DMA + ICTX, 0, 11, 0, ctl_bits=bsr, slot=slot))
    x.memwr(LADDER + 16, b"\x00" * 16)
    wipe_events(x)
    print("[4] AddressDevice BSR=1 slot=%d (same spot, target=1)" % slot)
    x.w64(x.OP + 0x18, 2)      # stop
    for _ in range(20):
        if not (x.rd(x.OP + 0x18) & 8):
            break
        time.sleep(0.01)
    x.w64(x.OP + 0x18, (x.DMA + LADDER) | 8)
    x.doorbell(0, 1)           # varied target
    ev = await_completion(x, tag="AddrDev")
    if ev is None:
        return 1
    if ev[2] != 1:
        print("    AddressDevice FAILED")
        return 1
    print("    CRCR-status after: %#x" % x.rd(x.OP + 0x18))
    out = x.memck(OCTX, 64)
    d = struct.unpack("<16I", out)
    print("    output ctx: %s" % " ".join("%08x" % v for v in d[:8]))
    print("    ep0 out    : %s" % " ".join("%08x" % v for v in d[8:14]))

    # rung 3: GET_DESCRIPTOR(device, 0x40) on the EP0 ring
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
    seen = set()
    found = None
    while time.time() - t0 < 5.0 and not found:
        for ev in scan_events(x):
            key = (ev[4], ev[5], ev[6])
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
    print(">>> transfer completed but descriptor looks wrong")
    return 1


if __name__ == "__main__":
    sys.exit(main())
