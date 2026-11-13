#!/usr/bin/env python3
"""SPEAK: Enable Slot -> Address Device (BSR=1, address 0) -> GET_DESCRIPTOR.

The full M2 gate unlocked by the OP+0x38 blast: slots provision on demand.
Contexts per the kernel's xhci_setup_addressable_virt_dev() layout:
  slot  DW0 = LAST_CTX(1) | SPEED(HS=3<<20) | route(0)
        DW1 = ROOT_HUB_PORT(2)          (bits 23:16!)
        DW3 = dev_state = 0 (device address 0)
  ep0   DW1 = MAX_PACKET(64)<<16 | EP_TYPE(CTRL=4)<<3 | CErr(3)<<1
        DW2 = ring deq ptr | DCS
        DW4 = avg TRB length 8
Address Device uses BSR=1: the xHC must NOT emit SET_ADDRESS on the wire, so
the A5 stays at address 0 - the Arduino-equivalent condition.

Usage: sudo python3 tools/xdc-3-speak.py <dma-base-hex>
"""
import struct
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from xdc import Xdc  # noqa: E402
from xdc3lib import bringup_v3, scan_events, wipe_events, LADDER  # noqa: E402

ICTX = 0x45000      # input context (ctrl+slot+ep0)
OCTX = 0x48000      # output device context region (chip writes here)
EPRING = 0x30000    # EP0 transfer ring (4K)
DATA = 0x50000      # data buffer


def show(ev):
    k, typ, cc, slot, param, status, control = ev
    return "ev[%3d] type=%d cc=%d slot=%d param=%#x status=%#x" % \
        (k, typ, cc, slot, param, status)


def wait_for(x, pred, timeout=6.0, verbose=True):
    t0 = time.time()
    seen = set()
    while time.time() - t0 < timeout:
        for ev in scan_events(x):
            key = (ev[0], ev[4], ev[5], ev[6])
            if key in seen:
                continue
            seen.add(key)
            if verbose:
                print("    " + show(ev))
            if pred(ev):
                return ev
        time.sleep(0.05)
    return None


def ctlop(code, slot, ctl_bits=0):
    return struct.pack("<QII", 0, 0, (0) | (code << 10) | ctl_bits |
                       ((slot & 0xFF) << 24))


def main():
    if len(sys.argv) < 2:
        print("usage: xdc-3-speak.py <dma-base-hex>")
        return 1
    x = Xdc(dma=int(sys.argv[1], 16))
    print("OP=%d slots=%d ports=%d scratch=%d" %
          (x.OP, x.maxslots, x.maxports, x.scratch))
    x.arm_irq()
    bringup_v3(x)
    print("[1] bringup v3 ok")

    # slot allocator gate (blast finding)
    x.wr(x.OP + 0x38, 0xFF)
    # port reset: A5 DFU re-attaches at high speed on root port 2
    ps = x.portsc(2)
    x.wr(x.OP + 0x400 + 0x10, ps | 0x10)
    t0 = time.time()
    while time.time() - t0 < 3:
        cur = x.portsc(2)
        if not ((cur >> 4) & 1) and ((cur >> 5) & 0xF) == 0 and (cur & 1):
            break
        time.sleep(0.01)
    cur = x.portsc(2)
    spd = (cur >> 10) & 0xF
    print("[2] port 2: CCS=%d PLS=%d SPD=%d" % (cur & 1, (cur >> 5) & 0xF, spd))
    if spd != 3:
        print("    WARNING: expected high speed (3)")

    # DCBAA[1] -> output ctx; input ctx built per kernel layout
    x.memwr(0x46000 + 8, struct.pack("<Q", x.DMA + OCTX))
    x.memwr(OCTX, b"\x00" * 0x1000)
    x.memwr(ICTX, b"\x00" * 0x60)
    slot_dw0 = 0x08000000 | (3 << 20)      # LAST_CTX(1) | speed HS
    slot_dw1 = (2 << 16)                   # ROOT_HUB_PORT(2)
    x.memwr(ICTX + 0x00, struct.pack("<I", 0x3))              # add ctx flags
    x.memwr(ICTX + 0x20, struct.pack("<7I", slot_dw0, slot_dw1, 0, 0, 0, 0, 0))
    ep0_dw1 = (64 << 16) | (4 << 3) | (3 << 1)                # MAXP|CTRL|CErr
    ep0_deq = (x.DMA + EPRING) | 1                            # ptr | DCS
    x.memwr(ICTX + 0x40, struct.pack("<6I", 0, ep0_dw1,
                                     ep0_deq & 0xFFFFFFFF, ep0_deq >> 32, 8, 0))

    # EP0 transfer ring: link back at [255], trbs armed below
    x.memwr(EPRING, b"\x00" * 0x1000)
    x.memwr(EPRING + 255 * 16,
            struct.pack("<QII", x.DMA + EPRING, 0, (1 << 0) | (1 << 1) | (6 << 10)))

    # command ladder: EnableSlot at TRB[0], AddressDevice(BSR=1) at TRB[1]
    x.memwr(LADDER, ctlop(9, 0))                       # Enable Slot cycle0
    bsr = 1 << 9
    x.memwr(LADDER + 16, struct.pack("<QII", x.DMA + ICTX, 0,
            0 | (11 << 10) | bsr | (1 << 24)))          # Address Device slot 1
    wipe_events(x)
    print("[3] rung 1: EnableSlot (doorbell #1)")
    x.doorbell(0)
    slot = None
    ev = wait_for(x, lambda e: e[1] == 33 and e[4] == x.DMA + LADDER, timeout=4)
    if ev is None:
        print("    no EnableSlot completion")
        return 1
    print("    EnableSlot: cc=%d slot=%d" % (ev[2], ev[3]))
    if ev[2] != 1 or ev[3] < 1:
        print("    EnableSlot failed")
        return 1
    slot = ev[3]

    print("    rung 2: AddressDevice BSR=1 (doorbell #2)")
    x.doorbell(0)
    ev2 = wait_for(x, lambda e: (e[1] == 33 and (e[4], e[5], e[6]) not in
                                 [(ev[4], ev[5], ev[6])]), timeout=4)
    if ev2 is None:
        print("    (no second completion seen)")
    else:
        print("    second completion: cc=%d slot=%d param=%#x" %
              (ev2[2], ev2[3], ev2[4]))
        if ev2[2] != 1:
            print("    AddressDevice FAILED cc=%d" % ev2[2])
    # read the chip-written output slot context (proof the slot is addressed)
    out = x.memck(OCTX, 64)
    d = struct.unpack("<16I", out)
    print("    output ctx @+%#x: %s" % (OCTX, " ".join("%08x" % v for v in d[:8])))
    print("    ep0 out ctx     : %s" % " ".join("%08x" % v for v in d[8:14]))
    print(">>> proceeding to GET_DESCRIPTOR (output ctx is the ground truth)")

    # GET_DESCRIPTOR(device, 0x40) @ address 0 via EP0 ring
    print("[4] GET_DESCRIPTOR via EP0 ring")
    setup = bytes([0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00])
    # SETUP TRB: type 2, IDT bit6, TRT=2 (IN) in status[17:16]
    x.memwr(EPRING, struct.pack("<Q", int.from_bytes(setup, "little")) +
            struct.pack("<II", (2 << 16), (1) | (2 << 10) | (1 << 6)))
    # DATA TRB: type 3, DIR_IN bit16, buffer, len 0x40
    x.memwr(EPRING + 16, struct.pack("<QII", x.DMA + DATA, 0x40,
            (1) | (3 << 10) | (1 << 16) | (1 << 5)))
    # STATUS TRB: type 4
    x.memwr(EPRING + 32, struct.pack("<QII", 0, 0,
            (1) | (4 << 10) | (1 << 5)))
    wipe_events(x)
    x.doorbell(slot, 1)

    ev = wait_for(x, lambda e: e[1] == 32 or (e[1] == 33 and e[2] != 1))
    if ev is None:
        print("    no transfer event")
        return 1
    if ev[1] == 33:
        print("    command completion instead of transfer: cc=%d" % ev[2])
        return 1
    trb_len = (ev[5] >> 17) & 0x1FFFF  # residual? transfer event status [31:17]
    print(">>> TRANSFER EVENT: cc=%d slot=%d ep=%#x status=%#x" %
          (ev[2], ev[3], (ev[6] >> 16) & 0x1F, ev[5]))
    got = x.memck(DATA, 0x40)
    print("    descriptor bytes:", got[:18].hex())
    if got[0] == 0x12:
        print("    idVendor=%#06x idProduct=%#06x" %
              (struct.unpack_from("<H", got, 8)[0],
               struct.unpack_from("<H", got, 10)[0]))
    if got[:4] == bytes.fromhex("12010040") or (got[8] | got[9] << 8) == 0x05AC:
        print(">>> THE A5 ANSWERED AT ADDRESS 0 - THE WALL IS DOWN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
