#!/usr/bin/env python3
"""POOL0 test: the xDC's DCBAA may be hardwired to the pool base.

Facts: commands never write the output ctx (silence says the chip does not
see OUR DCBAA at 0x46000); transfers need DCBAA[slot] and produce nothing.
v1-era evidence (the original bringup) had the DCBAA AT POOL+0x0 and the old
"storm" walked exactly through it - consistent with the chip reading that
area as table+commands. Test: DCBAA at pool+0 (entries 0/1 seeded), command
ladder moved to pool+0x60000, then GET_DESCRIPTOR - the descriptor transfer
is the verdict.

Usage: sudo python3 tools/xdc-3-pool0.py <dma-base-hex>
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
LAD = 0x60000          # the command ladder, away from the pool-base tables
SPARR = 0x47000


def bringup_v5(x):
    assert x.hcrst(), "HCRST failed"
    assert x.halt(), "halt failed"
    D = x.DMA
    x.memwr(SPARR, b"".join(struct.pack("<Q", D + x.SPPG + i * 0x1000)
                            for i in range(x.scratch)))
    # DCBAA AT THE POOL BASE
    x.memwr(0x0, struct.pack("<Q", D + SPARR) +          # [0] scratch array
            struct.pack("<Q", D + OCTX) +                 # [1] slot 1 ctx
            b"\x00" * (512 - 16))
    x.memwr(LAD, b"\x00" * 0x1000)
    x.memwr(LAD + 255 * 16,
            struct.pack("<QII", D + LAD, 0, (1 << 0) | (1 << 1) | (6 << 10)))
    x.memwr(x.EVTR, b"\x00" * 0x1000)
    x.memwr(x.EVTR + 255 * 16,
            struct.pack("<QII", D + x.EVTR, 0, (1 << 1) | (6 << 10)))
    x.memwr(x.ERST, struct.pack("<QII", D + x.EVTR, 256, 0))
    x.wr(x.OP + 0x20, x.maxslots | (min(x.scratch, 0x1F) << 25))
    x.w64(x.OP + 0x10, D + 0x0)          # (swapped-role) DCBAA reg
    x.w64(x.OP + 0x18, (D + LAD) | 1)     # command ring at LAD, RCS=1
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
        print("usage: xdc-3-pool0.py <dma-base-hex>")
        return 1
    x = Xdc(dma=int(sys.argv[1], 16))
    print("OP=%d slots=%d ports=%d scratch=%d" %
          (x.OP, x.maxslots, x.maxports, x.scratch))
    x.arm_irq()
    bringup_v5(x)
    x.wr(x.OP + 0x38, 0xFF)
    print("[1] bringup v5: DCBAA at pool+0, ladder at +0x60000")

    ps = x.portsc(2)
    x.wr(x.OP + 0x400 + 0x10, ps | 0x10)
    t0 = time.time()
    while time.time() - t0 < 3:
        cur = x.portsc(2)
        if not ((cur >> 4) & 1) and ((cur >> 5) & 0xF) == 0 and (cur & 1):
            break
        time.sleep(0.01)
    print("[2] port 2: SPD=%d" % ((x.portsc(2) >> 10) & 0xF))

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

    # the chain at LAD
    x.memwr(LAD, x.trb(0, 0, 9, 1))
    x.memwr(LAD + 16, x.trb(x.DMA + ICTX, 0, 11, 1, slot=1))
    L.wipe_events(x)
    x.doorbell(0)
    print("[3] chain")
    ev1 = await_comp(x, tag="EnSlot")
    if ev1 is None or ev1[2] != 1 or ev1[3] < 1:
        return 1
    slot = ev1[3]
    if slot != 1:
        print("    slot %d, rerun" % slot)
        return 1
    ev2 = await_comp(x, tag="AddrDev")
    if ev2 is None or ev2[2] != 1:
        return 1
    d = struct.unpack("<8I", x.memck(OCTX, 32))
    print("    OCTX: %s" % " ".join("%08x" % v for v in d))
    print(">>> addressed (chain, pool0 DCBAA)")

    print("[4] GET_DESCRIPTOR @ address 0")
    setup = bytes([0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00])
    # SETUP: param = 8 setup bytes (IDT), w2 = TRB_LEN(8), ctl = IDT|TX_TYPE(3)|CHAIN
    x.memwr(EPRING, struct.pack("<QII", int.from_bytes(setup, "little"),
            8, 1 | (3 << 16) | (1 << 6) | (1 << 4) | (2 << 10)))
    # DATA: param = buf, w2 = TRB_LEN(0x40), ctl = DIR_IN|ISP|CHAIN|DATA
    x.memwr(EPRING + 16, struct.pack("<QII", x.DMA + DATA, 0x40,
            1 | (1 << 16) | (1 << 2) | (1 << 4) | (3 << 10)))
    # STATUS: ctl = IOC|STATUS stage (OUT for a control read), no chain
    x.memwr(EPRING + 32, struct.pack("<QII", 0, 0, 1 | (4 << 10) | (1 << 5)))
    L.wipe_events(x)
    x.doorbell(slot, 1)
    t0 = time.time()
    seen = set()
    found = None
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
    got = x.memck(DATA, 0x40)
    print("    DATA: %s" % got[:18].hex())
    if found:
        vend = struct.unpack_from("<H", got, 8)[0] if len(got) >= 10 else 0
        print("    idVendor=%#06x" % vend)
        if vend == 0x05AC:
            print(">>> THE A5 ANSWERED AT ADDRESS 0 - THE WALL IS DOWN")
            return 0
    print(">>> no transfer evidence")
    return 1


if __name__ == "__main__":
    sys.exit(main())
