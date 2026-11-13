#!/usr/bin/env python3
"""DEVICE: the full corrected flow with the die's true register map.

xdc3lib.bringup_v3 is now v6: DCBAAP at OP+0x30, MaxSlotsEn at OP+0x38,
USBCMD with INTE - all confirmed via /dev/mem ground truth of the kernel's
working configuration. Chain EnableSlot -> AddressDevice(BSR=1, DevAddr=0,
device stays at address 0: NO SET_ADDRESS on the wire) -> GET_DESCRIPTOR
via kernel-exact chained transfer TRBs.

Usage: sudo python3 tools/xdc-3-device.py <dma-base-hex>
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
        print("usage: xdc-3-device.py <dma-base-hex>")
        return 1
    x = Xdc(dma=int(sys.argv[1], 16))
    print("OP=%d slots=%d ports=%d scratch=%d" %
          (x.OP, x.maxslots, x.maxports, x.scratch))
    x.arm_irq()
    L.bringup_v3(x)
    print("[1] bringup v6 (true map) ok")

    ps = x.portsc(2)
    if not (ps & 1):
        print("    port 2 has nothing attached")
        return 1
    x.wr(x.OP + 0x400 + 0x10, ps | 0x10)
    t0 = time.time()
    while time.time() - t0 < 3:
        cur = x.portsc(2)
        if not ((cur >> 4) & 1) and ((cur >> 5) & 0xF) == 0 and (cur & 1):
            break
        time.sleep(0.01)
    cur = x.portsc(2)
    print("[2] port 2: CCS=%d PLS=%d SPD=%d" %
          (cur & 1, (cur >> 5) & 0xF, (cur >> 10) & 0xF))

    # slot 1 output ctx + input context (kernel-exact)
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
    x.memwr(EPRING + 255 * 16,
            struct.pack("<QII", x.DMA + EPRING, 0, (1 << 0) | (1 << 1) | (6 << 10)))

    # chain at the ladder
    x.memwr(L.LADDER, x.trb(0, 0, 9, 1))
    x.memwr(L.LADDER + 16, x.trb(x.DMA + ICTX, 0, 11, 1, ctl_bits=1 << 9, slot=1))
    L.wipe_events(x)
    x.doorbell(0)
    print("[3] chain: EnableSlot -> AddressDevice(BSR=1)")
    ev1 = await_comp(x, tag="EnSlot")
    if ev1 is None or ev1[2] != 1 or ev1[3] < 1:
        return 1
    slot = ev1[3]
    if slot != 1:
        print("    slot=%d (need 1 for pre-laid chain)" % slot)
        return 1
    ev2 = await_comp(x, tag="AddrDev")
    if ev2 is None or ev2[2] != 1:
        print("    AddressDevice failed")
        return 1
    d = struct.unpack("<8I", x.memck(OCTX, 32))
    print("    OCTX dword: %s" % " ".join("%08x" % v for v in d))
    print(">>> SLOT 1 ADDRESSED, DEVICE AT ADDRESS 0 (no SET_ADDRESS on wire)")

    # GET_DESCRIPTOR (device, 0x40) - kernel-exact chained TRBs
    print("[4] GET_DESCRIPTOR @ address 0")
    setup = bytes([0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00])
    x.memwr(DATA, b"\x00" * 0x100)
    x.memwr(EPRING, struct.pack("<QII", int.from_bytes(setup, "little"),
            8, 1 | (3 << 16) | (1 << 6) | (1 << 4) | (2 << 10)))
    x.memwr(EPRING + 16, struct.pack("<QII", x.DMA + DATA, 0x40,
            1 | (1 << 16) | (1 << 2) | (1 << 4) | (3 << 10)))
    x.memwr(EPRING + 32, struct.pack("<QII", 0, 0, 1 | (4 << 10) | (1 << 5)))
    L.wipe_events(x)
    x.doorbell(slot, 1)
    t0 = time.time()
    seen = set()
    found = None
    while time.time() - t0 < 8.0 and not found:
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
    if found and found[2] == 1:
        vend = struct.unpack_from("<H", got, 8)[0] if len(got) >= 10 else 0
        print("    idVendor=%#06x idProduct=%#06x" %
              (vend, struct.unpack_from("<H", got, 10)[0]))
        if vend == 0x05AC:
            print(">>> THE A5 ANSWERED AT ADDRESS 0 - THE WALL IS DOWN")
            return 0
    print(">>> transfer did not complete")
    return 1


if __name__ == "__main__":
    sys.exit(main())
