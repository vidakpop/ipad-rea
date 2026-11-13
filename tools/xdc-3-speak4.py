#!/usr/bin/env python3
"""SPEAK4: engine model v8 - pointer latched at bring-up, one fetch per
doorbell(0,0), pointer rewritable only while stopped (after cc=24 settles).

Rung 2 protocol (the fix): CS-stop -> confirm stopped (cc=24 event) ->
rewrite pointer to the AddressDevice TRB -> doorbell(0, 0) -> completion.

Usage: sudo python3 tools/xdc-3-speak4.py <dma-base-hex>
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


def await_comp(x, timeout=6.0, tag="", expect_param=None):
    """Wait for a command completion; anything at the fetch spot (param match)
    is REAL and must be returned even with storm-y completion codes."""
    t0 = time.time()
    seen = set()
    while time.time() - t0 < timeout:
        for ev in scan_events(x):
            key = (ev[0], ev[4], ev[5], ev[6])
            if key in seen:
                continue
            seen.add(key)
            if ev[1] != 33:
                continue
            if expect_param is not None and ev[4] == expect_param:
                print("    %-10s cc=%d slot=%d param=%#x (FETCH SPOT)" %
                      (tag, ev[2], ev[3], ev[4]))
                return ev
            if expect_param is None and ev[2] not in (5, 24):
                print("    %-10s cc=%d slot=%d param=%#x" %
                      (tag, ev[2], ev[3], ev[4]))
                return ev
        time.sleep(0.05)
    print("    %-10s NO COMPLETION" % tag)
    return None


def stop_ring(x, wait=2.0):
    x.w64(x.OP + 0x18, 2)  # CS: stop request
    t0 = time.time()
    while time.time() - t0 < wait:
        for ev in scan_events(x):
            if ev[1] == 33 and ev[2] == 24:
                return True
        time.sleep(0.02)
    return False


def main():
    if len(sys.argv) < 2:
        print("usage: xdc-3-speak4.py <dma-base-hex>")
        return 1
    x = Xdc(dma=int(sys.argv[1], 16))
    print("OP=%d slots=%d ports=%d scratch=%d" %
          (x.OP, x.maxslots, x.maxports, x.scratch))
    x.arm_irq()
    bringup_v3(x)
    x.wr(x.OP + 0x38, 0xFF)
    print("[1] bringup ok")

    ps = x.portsc(2)
    x.wr(x.OP + 0x400 + 0x10, ps | 0x10)
    t0 = time.time()
    while time.time() - t0 < 3:
        cur = x.portsc(2)
        if not ((cur >> 4) & 1) and ((cur >> 5) & 0xF) == 0 and (cur & 1):
            break
        time.sleep(0.01)
    print("[2] port 2: SPD=%d" % ((x.portsc(2) >> 10) & 0xF))

    x.memwr(0x46000 + 8, struct.pack("<Q", x.DMA + OCTX))
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

    # rung 1: EnableSlot (fetch at latched pointer = LADDER base)
    x.memwr(LADDER, x.trb(0, 0, 9, 0))
    x.memwr(LADDER + 16, b"\x00" * 16)
    wipe_events(x)
    x.doorbell(0)
    print("[3] EnableSlot")
    ev = await_comp(x, tag="EnSlot")
    if ev is None or ev[2] != 1 or ev[3] < 1:
        return 1
    slot = ev[3]

    # rung 2: overwrite TRB[0]; the stop cycle must produce its cc=24 event,
    # which re-arms the doorbell, then restart+doorbell fetches the new TRB.
    print("[4] AddressDevice BSR=1 slot=%d (stop->cc24->restart->doorbell)"
          % slot)
    bsr = 1 << 9
    x.memwr(LADDER, x.trb(x.DMA + ICTX, 0, 11, 0, ctl_bits=bsr, slot=slot))
    x.memwr(LADDER + 16, b"\x00" * 16)
    got24 = False
    for attempt in range(6):
        wipe_events(x)
        x.w64(x.OP + 0x18, 2)  # CS stop request
        t0 = time.time()
        while time.time() - t0 < 1.2:
            for ev in scan_events(x):
                if ev[1] == 33 and ev[2] == 24:
                    got24 = True
                    print("    stop event cycle %d: param=%#x" %
                          (attempt, ev[4]))
                    break
            if got24:
                break
            time.sleep(0.02)
        if got24:
            break
        time.sleep(0.3)
    if not got24:
        print("    WARNING: no stop event after 6 tries")
    x.w64(x.OP + 0x18, (x.DMA + LADDER) | 8)  # restart (pointer inert)
    time.sleep(0.05)
    x.doorbell(0)
    ev = await_comp(x, tag="AddrDev", expect_param=x.DMA + LADDER)
    if ev is None:
        return 1
    if ev[2] != 1:
        print("    AddressDevice FAILED cc=%d" % ev[2])
        return 1
    out = x.memck(OCTX, 64)
    d = struct.unpack("<16I", out)
    print("    output ctx DWs : %s" % " ".join("%08x" % v for v in d[:8]))
    print("    ep0 ctx DWs    : %s" % " ".join("%08x" % v for v in d[8:14]))
    print(">>> SLOT %d ADDRESSED AT DEVICE ADDRESS 0 (BSR=1)" % slot)

    # rung 3: GET_DESCRIPTOR
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
    print(">>> transfer completed; idVendor=%#x" % vend)
    return 0


if __name__ == "__main__":
    sys.exit(main())
