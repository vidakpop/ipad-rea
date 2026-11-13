#!/usr/bin/env python3
"""THE LADDER: feed real command TRBs to the chip's own command walk.

Forensics (xdc-3-dump/xdump-3-events):
 - the xDC ignores our CRCR ring layout; after HCRST+RUN it walks a command
   ring starting at pool+0x0 (the value we wrote into DCBAAP), consuming TRBs
   16 bytes at a time (~8 ms/step), never halting on TRB-error (AMD quirk).
 - every consumed fetch deposits a Command Completion event in the event ring.
 - walk TRBs are executed when their cycle bit == 0 (RCS state 0), which is how
   the garbage got "executed".

So: DCBAA moves to pool+0x46000, and pool+0x0..0x1000 becomes the real
command ladder the chip walks through. First rung: Enable Slot (type 9,
cycle 0). Full event-ring scan finds its completion. cc=1 + slot id = M2 gate.

Usage: sudo python3 tools/xdc-3-ladder.py <dma-base-hex>
"""
import struct
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from xdc import Xdc  # noqa: E402

EVENT_TYPES = {
    32: "TRANSFER", 33: "CMD_COMPLETION", 34: "PORT_STATUS", 36: "STREAM",
    37: "MFWR", 39: "MFINDEX_WRAP",
}

DCBAA_V2 = 0x46000   # relocated: pool+0..0x1000 becomes the command ladder
SPARR_V2 = 0x47000
LADDER = 0x0         # where the chip actually walks


def bringup_v2(x):
    """Full cold bring-up with the DCBAA relocated out of the walk path."""
    assert x.hcrst(), "HCRST failed"
    assert x.halt(), "halt failed"
    D = x.DMA
    # scratchpad array: 64 pointers at SPARR_V2, pages stay at 0x2000..0x42000
    x.memwr(SPARR_V2, b"".join(struct.pack("<Q", D + x.SPPG + i * 0x1000)
                               for i in range(x.scratch)))
    # DCBAA at 0x46000: entry 0 = scratchpad array ptr, rest zero
    x.memwr(DCBAA_V2, struct.pack("<Q", D + SPARR_V2) + b"\x00" * (512 - 8))
    # command ladder at pool+0: zeros for now; LINK at its 256th TRB back to 0
    x.memwr(LADDER, b"\x00" * 0x1000)
    x.memwr(LADDER + 255 * 16,
            struct.pack("<QII", D + LADDER, 0, (0 << 0) | (1 << 1) | (6 << 10)))
    # event ring (unchanged, verified working)
    x.memwr(x.EVTR, b"\x00" * 0x1000)
    x.memwr(x.EVTR + 255 * 16,
            struct.pack("<QII", D + x.EVTR, 0, (1 << 1) | (6 << 10)))
    x.memwr(x.ERST, struct.pack("<QII", D + x.EVTR, 256, 0))
    x.wr(x.OP + 0x20, x.maxslots | (min(x.scratch, 0x7F) << 25))
    x.w64(x.OP + 0x18, D + DCBAA_V2)   # DCBAAP -> relocated
    x.w64(x.OP + 0x10, D + LADDER)     # CRCR points where the chip walks anyway
    x.wr(x.RTS + 0x20 + 0x08, 1)
    x.w64(x.RTS + 0x20 + 0x10, D + x.ERST)
    x.w64(x.RTS + 0x20 + 0x18, D + x.EVTR)
    x.wr(x.RTS + 0x20 + 0x00, 0x2)
    assert x.run(), "controller did not run"


def scan_events(x, verbose=False):
    """Scan the WHOLE event page; return [(idx, type, cc, slot, param, status, control)] for cycle=1."""
    out = []
    page = x.memck(x.EVTR, 0x1000)
    for k in range(256):
        param, status, control = struct.unpack_from("<QII", page, 16 * k)
        if control & 1:
            typ = (control >> 10) & 0x3F
            cc = (status >> 24) & 0xFF
            slot = (control >> 24) & 0xFF
            out.append((k, typ, cc, slot, param, status, control))
            if verbose:
                print("    ev[%3d] type=%2d %-13s cc=%2d slot=%2d param=%#x" %
                      (k, typ, EVENT_TYPES.get(typ, "?"), cc, slot, param))
    return out


def main():
    if len(sys.argv) < 2:
        print("usage: xdc-3-ladder.py <dma-base-hex>")
        return 1
    x = Xdc(dma=int(sys.argv[1], 16))
    print("OP=%d slots=%d ports=%d scratch=%d" %
          (x.OP, x.maxslots, x.maxports, x.scratch))
    x.arm_irq()
    bringup_v2(x)
    print("[1] bringup v2 ok: DCBAA at +0x46000, ladder at +0x0000")

    print("[2] re-attaching the iPad: bus reset on port 2")
    ps = x.portsc(2)
    if not (ps & 1):
        print("    ERROR: nothing on port 2")
        return 1
    x.wr(x.OP + 0x400 + 0x10, ps | 0x10)  # PR
    t0 = time.time()
    while time.time() - t0 < 3:
        cur = x.portsc(2)
        if not ((cur >> 4) & 1) and ((cur >> 5) & 0xF) == 0 and (cur & 1):
            break
        time.sleep(0.01)
    cur = x.portsc(2)
    spd = (cur >> 10) & 0xF
    print("    port 2: CCS=%d PLS=%d SPD=%d" % (cur & 1, (cur >> 5) & 0xF, spd))

    # reset the event page so we only see the Enable Slot completions
    x.memwr(x.EVTR, b"\x00" * 0x1000)
    x.w64(x.RTS + 0x20 + 0x18, x.DMA + x.EVTR)

    print("[3] ladder rung 0: Enable Slot, cycle=0, at pool+0x0")
    x.memwr(LADDER, x.trb(0, 0, 9, 0))  # Enable Slot, cycle 0
    x.doorbell(0)

    print("[4] full event scan (up to 6 s)")
    t0 = time.time()
    seen = set()
    winners = []
    while time.time() - t0 < 6.0:
        for (k, typ, cc, slot, param, status, control) in scan_events(x):
            if (k, param, status, control) in seen:
                continue
            seen.add((k, param, status, control))
            name = EVENT_TYPES.get(typ, "?")
            if typ == 33:
                print("    ev[%3d] CMD_COMPLETION  cc=%2d slot=%2d param=%#x" %
                      (k, cc, slot, param))
                if cc == 1 and slot > 0:
                    winners.append(slot)
                    print(">>> M2 UNLOCKED: ENABLE SLOT SUCCEEDED, slot=%d" % slot)
                    with open("/tmp/xdc-slot-id", "w") as f:
                        f.write(str(slot))
                    return 0
            elif typ == 34:
                print("    ev[%3d] PORT_STATUS     cc=%2d slot=%2d param=%#x" %
                      (k, cc, slot, param))
            else:
                print("    ev[%3d] %-14s cc=%2d slot=%2d param=%#x" %
                      (k, name, cc, slot, param))
        time.sleep(0.1)
    print(">>> no Enable Slot success within 6 s")
    return 1


if __name__ == "__main__":
    sys.exit(main())
