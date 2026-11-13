#!/usr/bin/env python3
"""THE LADDER v2: swapped DCBAAP/CRCR bring-up + Enable Slot rung.

Forensic proof (xdc-3-ladder.py): the chip's command walk starts at whatever
value we write to OP+0x18 (the "DCBAAP" slot), and ignores our "CRCR" write at
OP+0x10. Two different DCBAAP values -> walk follows both times. On this AMD
xDC alias the two qwords' roles are swapped relative to the spec.

Fix: write the DCBAA address to OP+0x10 and the command ring to OP+0x18.
Then the chip walks OUR ring with OUR TRBs. Rung 0: Enable Slot (cycle 0).

Usage: sudo python3 tools/xdc-3-ladder2.py <dma-base-hex>
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

DCBAA_V2 = 0x46000   # real device context array lives here
SPARR_V2 = 0x47000
LADDER = 0x0         # our true command ring, where the chip now walks


def bringup_v3(x):
    assert x.hcrst(), "HCRST failed"
    assert x.halt(), "halt failed"
    D = x.DMA
    x.memwr(SPARR_V2, b"".join(struct.pack("<Q", D + x.SPPG + i * 0x1000)
                               for i in range(x.scratch)))
    x.memwr(DCBAA_V2, struct.pack("<Q", D + SPARR_V2) + b"\x00" * (512 - 8))
    # command ring at pool+0: Enable Slot at TRB[0], zeros behind
    x.memwr(LADDER, b"\x00" * 0x1000)
    x.memwr(LADDER + 255 * 16,
            struct.pack("<QII", D + LADDER, 0, (0 << 0) | (1 << 1) | (6 << 10)))
    x.memwr(x.EVTR, b"\x00" * 0x1000)
    x.memwr(x.EVTR + 255 * 16,
            struct.pack("<QII", D + x.EVTR, 0, (1 << 1) | (6 << 10)))
    x.memwr(x.ERST, struct.pack("<QII", D + x.EVTR, 256, 0))
    x.wr(x.OP + 0x20, x.maxslots | (min(x.scratch, 0x7F) << 25))
    # THE SWAP: OP+0x10 = DCBAA, OP+0x18 = command ring (empirically true)
    x.w64(x.OP + 0x10, D + DCBAA_V2)
    x.w64(x.OP + 0x18, D + LADDER)
    x.wr(x.RTS + 0x20 + 0x08, 1)
    x.w64(x.RTS + 0x20 + 0x10, D + x.ERST)
    x.w64(x.RTS + 0x20 + 0x18, D + x.EVTR)
    x.wr(x.RTS + 0x20 + 0x00, 0x2)
    assert x.run(), "controller did not run"


def scan_events(x):
    out = []
    page = x.memck(x.EVTR, 0x1000)
    for k in range(256):
        param, status, control = struct.unpack_from("<QII", page, 16 * k)
        if control & 1:
            typ = (control >> 10) & 0x3F
            cc = (status >> 24) & 0xFF
            slot = (control >> 24) & 0xFF
            out.append((k, typ, cc, slot, param, status, control))
    return out


def main():
    if len(sys.argv) < 2:
        print("usage: xdc-3-ladder2.py <dma-base-hex>")
        return 1
    x = Xdc(dma=int(sys.argv[1], 16))
    print("OP=%d slots=%d ports=%d scratch=%d" %
          (x.OP, x.maxslots, x.maxports, x.scratch))
    x.arm_irq()
    bringup_v3(x)
    print("[1] bringup v3 (swapped DCBAAP/CRCR) ok")

    print("[2] bus reset port 2 (iPad)")
    ps = x.portsc(2)
    if not (ps & 1):
        print("    ERROR: nothing on port 2")
        return 1
    x.wr(x.OP + 0x400 + 0x10, ps | 0x10)
    t0 = time.time()
    while time.time() - t0 < 3:
        cur = x.portsc(2)
        if not ((cur >> 4) & 1) and ((cur >> 5) & 0xF) == 0 and (cur & 1):
            break
        time.sleep(0.01)
    cur = x.portsc(2)
    print("    port 2: CCS=%d PLS=%d SPD=%d" % (cur & 1, (cur >> 5) & 0xF,
                                                (cur >> 10) & 0xF))

    x.memwr(x.EVTR, b"\x00" * 0x1000)
    x.w64(x.RTS + 0x20 + 0x18, x.DMA + x.EVTR)

    print("[3] rung 0: Enable Slot type=9 cycle=0 at pool+0x0")
    x.memwr(LADDER, x.trb(0, 0, 9, 0))
    x.doorbell(0)

    t0 = time.time()
    seen = set()
    while time.time() - t0 < 8.0:
        for (k, typ, cc, slot, param, status, control) in scan_events(x):
            if (k, param, status, control) in seen:
                continue
            seen.add((k, param, status, control))
            if typ == 33:
                print("    ev[%3d] CMD_COMPLETION cc=%2d slot=%2d param=%#x" %
                      (k, cc, slot, param))
                if cc == 1 and slot > 0:
                    print(">>> M2 UNLOCKED: ENABLE SLOT OK, slot=%d" % slot)
                    # verify the chip provisioned DCBAA[slot]
                    d = x.memck(DCBAA_V2 + 16 * 0, 16)
                    print("    DCBAA[0..1]: %s" % d.hex())
                    with open("/tmp/xdc-slot-id", "w") as f:
                        f.write(str(slot))
                    return 0
            elif typ == 34:
                print("    ev[%3d] PORT_STATUS cc=%2d" % (k, cc))
            else:
                print("    ev[%3d] %s cc=%2d param=%#x" %
                      (k, EVENT_TYPES.get(typ, "?"), cc, param))
        time.sleep(0.1)
    print(">>> no Enable Slot success within 8 s")
    return 1


if __name__ == "__main__":
    sys.exit(main())
