#!/usr/bin/env python3
"""SPEAK5: canonical xHCI cycle plan - RCS=1 + cycle-1 TRBs.

Tonight's cycle-0/RCS-0 plan made the engine fetch exactly one command per
RUN and chew zeros as garbage (the cc=5 storm). Canonical flow: set CRCR
RCS=1, lay all command TRBs with cycle=1; the engine chains fetches, silent-
skips zeros, and stays open for commands laid ahead of it.
Chain: TRB[0] EnableSlot(cyc1) -> TRB[1] AddressDevice BSR=1 (cyc1).
Then GET_DESCRIPTOR at address 0 through the EP0 ring doorbell.

Usage: sudo python3 tools/xdc-3-speak5.py <dma-base-hex>
"""
import struct
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import xdc3lib as L  # noqa: E402
from xdc import Xdc  # noqa: E402

ICTX = 0x45000
OCTX = 0x48000
EPRING = 0x30000
DATA = 0x50000


def bringup_v4(x):
    assert x.hcrst(), "HCRST failed"
    assert x.halt(), "halt failed"
    D = x.DMA
    x.memwr(L.SPARR_V2, b"".join(struct.pack("<Q", D + x.SPPG + i * 0x1000)
                                for i in range(x.scratch)))
    x.memwr(L.DCBAA_V2, struct.pack("<Q", D + L.SPARR_V2) + b"\x00" * (512 - 8))
    x.memwr(L.LADDER, b"\x00" * 0x1000)
    x.memwr(L.LADDER + 255 * 16,
            struct.pack("<QII", D + L.LADDER, 0, (1 << 0) | (1 << 1) | (6 << 10)))
    x.memwr(x.EVTR, b"\x00" * 0x1000)
    x.memwr(x.EVTR + 255 * 16,
            struct.pack("<QII", D + x.EVTR, 0, (1 << 1) | (6 << 10)))
    x.memwr(x.ERST, struct.pack("<QII", D + x.EVTR, 256, 0))
    x.wr(x.OP + 0x20, x.maxslots | (min(x.scratch, 0x7F) << 25))
    x.w64(x.OP + 0x10, D + L.DCBAA_V2)
    # CANONICAL: command ring pointer WITH RCS=1
    x.w64(x.OP + 0x18, (D + L.LADDER) | 1)
    x.wr(x.RTS + 0x20 + 0x08, 1)
    x.w64(x.RTS + 0x20 + 0x10, D + x.ERST)
    x.w64(x.RTS + 0x20 + 0x18, (D + x.EVTR) | 8)
    x.wr(x.RTS + 0x20 + 0x00, 0x2)
    assert x.run(), "controller did not run"


def await_comp(x, timeout=8.0, tag=""):
    t0 = time.time()
    seen = set()
    while time.time() - t0 < timeout:
        for ev in L.scan_events(x):
            key = (ev[0], ev[4], ev[5], ev[6])
            if key in seen:
                continue
            seen.add(key)
            if ev[1] == 33 and ev[2] not in (5, 24):
                print("    %-10s cc=%d slot=%d param=%#x" %
                      (tag, ev[2], ev[3], ev[4]))
                return ev
        time.sleep(0.05)
    print("    %-10s NO COMPLETION" % tag)
    return None


def main():
    if len(sys.argv) < 2:
        print("usage: xdc-3-speak5.py <dma-base-hex>")
        return 1
    x = Xdc(dma=int(sys.argv[1], 16))
    print("OP=%d slots=%d ports=%d scratch=%d" %
          (x.OP, x.maxslots, x.maxports, x.scratch))
    x.arm_irq()
    bringup_v4(x)
    x.wr(x.OP + 0x38, 0xFF)
    print("[1] bringup v4 (RCS=1, cycle-1 ladder)")

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
    x.memwr(L.DCBAA_V2 + 8, struct.pack("<Q", x.DMA + OCTX))
    x.memwr(OCTX, b"\x00" * 0x1000)
    x.memwr(ICTX, b"\x00" * 0x60)
    x.memwr(ICTX + 0x00, struct.pack("<I", 0x3))
    x.memwr(ICTX + 0x20, struct.pack("<7I", 0x08000000 | (3 << 20), 2 << 16,
                                     0, 0, 0, 0, 0))
    ep0_dw1 = (64 << 16) | (4 << 3) | (3 << 1)
    ep0_deq = (x.DMA + EPRING) | 1
    x.memwr(ICTX + 0x40, struct.pack("<6I", 0, ep0_dw1,
                                     ep0_deq & 0xFFFFFFFF, ep0_deq >> 32, 8, 0))
    x.memwr(EPRING, b"\x00" * 0x1000)

    # the chain: TRB[0] EnableSlot(cyc1), TRB[1] AddrDev BSR=1(cyc1, slot guess 1)
    x.memwr(L.LADDER, x.trb(0, 0, 9, 1))
    bsr = 0  # BSR=0: full addressing path, DevAddr=0 (the only wire-visible SET_ADDRESS)
    x.memwr(L.LADDER + 16, x.trb(x.DMA + ICTX, 0, 11, 1, slot=1))
    L.wipe_events(x)
    x.doorbell(0)

    print("[3] chain: EnableSlot then AddressDevice")
    ev = await_comp(x, tag="EnSlot")
    if ev is None or ev[2] != 1 or ev[3] < 1:
        return 1
    slot = ev[3]
    if slot != 1:
        print("    slot=%d (chain guessed 1) - rerun needed" % slot)
        return 1
    ev2 = await_comp(x, tag="AddrDev")
    if ev2 is None:
        return 1
    if ev2[2] != 1:
        print("    AddrDev cc=%d" % ev2[2])
        return 1
    out = x.memck(OCTX, 64)
    d = struct.unpack("<16I", out)
    print("    output ctx: %s" % " ".join("%08x" % v for v in d[:8]))
    print(" >>> SLOT 1 ADDRESSED AT DEVICE ADDRESS 0 (BSR=1)")

    # GET_DESCRIPTOR over the EP0 ring (doorbell slot,1)
    print("[4] GET_DESCRIPTOR @ address 0")
    setup = bytes([0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00])
    x.memwr(EPRING, struct.pack("<Q", int.from_bytes(setup, "little")) +
            struct.pack("<II", (2 << 16), (1) | (2 << 10) | (1 << 6)))
    x.memwr(EPRING + 16, struct.pack("<QII", x.DMA + DATA, 0x40,
            (1) | (3 << 10) | (1 << 16) | (1 << 5)))
    x.memwr(EPRING + 32, struct.pack("<QII", 0, 0, (1) | (4 << 10) | (1 << 5)))
    L.wipe_events(x)
    x.doorbell(slot, 1)
    t0 = time.time()
    found = None
    seen = set()
    while time.time() - t0 < 6.0 and not found:
        for ev in L.scan_events(x):
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
    print(">>> transfer completed; idVendor=%#x" % vend)
    return 0


if __name__ == "__main__":
    sys.exit(main())
