"""Shared xDC .3 library: bring-up v3 (swapped DCBAAP/CRCR) + full event scan."""
import struct
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from xdc import Xdc  # noqa: E402

DCBAA_V2 = 0x46000
SPARR_V2 = 0x47000
LADDER = 0x0

EVENT_TYPES = {
    32: "TRANSFER", 33: "CMD_COMPLETION", 34: "PORT_STATUS", 36: "STREAM",
    37: "MFWR", 39: "MFINDEX_WRAP",
}


def bringup_v3(x):
    """Bring-up v6 - the die's TRUE register map. Ground truth captured via
    /dev/mem from the live kernel xhci_hcd configuration (fb200000+0x20..):
      OP+0x18 = CRCR pointer (write) / status (read)
      OP+0x30 = DCBAAP (64-bit!)   <- never before written by us
      OP+0x38 = MaxSlotsEn (0x40)
      USBCMD  = RS | INTE (bit 2) when running (kernel: 0x5)
    """
    assert x.hcrst(), "HCRST failed"
    assert x.halt(), "halt failed"
    D = x.DMA
    x.memwr(SPARR_V2, b"".join(struct.pack("<Q", D + x.SPPG + i * 0x1000)
                               for i in range(x.scratch)))
    x.memwr(DCBAA_V2, struct.pack("<Q", D + SPARR_V2) + b"\x00" * (512 - 8))
    x.memwr(LADDER, b"\x00" * 0x1000)
    x.memwr(LADDER + 255 * 16,
            struct.pack("<QII", D + LADDER, 0, (1 << 0) | (1 << 1) | (6 << 10)))
    x.memwr(x.EVTR, b"\x00" * 0x1000)
    x.memwr(x.EVTR + 255 * 16,
            struct.pack("<QII", D + x.EVTR, 0, (1 << 1) | (6 << 10)))
    x.memwr(x.ERST, struct.pack("<QII", D + x.EVTR, 256, 0))
    # TRUE MAP (kernel ground truth from the bind-time /dev/mem trace)
    x.wr(x.OP + 0x14, 0x2)             # kernel writes 2 here early (unknown semantic)
    x.w64(x.OP + 0x30, D + DCBAA_V2)   # DCBAAP is here on this die
    x.wr(x.OP + 0x38, 0x40)            # MaxSlotsEn = 64
    x.w64(x.OP + 0x18, (D + LADDER) | 1)  # command ring, RCS=1
    x.wr(x.RTS + 0x20 + 0x08, 1)
    x.w64(x.RTS + 0x20 + 0x10, D + x.ERST)
    x.w64(x.RTS + 0x20 + 0x18, D + x.EVTR)
    x.wr(x.RTS + 0x20 + 0x00, 0x2)
    # RUN with INTE (bit 2), mirroring the kernel's live USBCMD=0x5
    x.wr(x.OP + 0x00, 0x5)
    time.sleep(0.05)
    assert not (x.rd(x.OP + 4) & 1), "controller did not run"


def bringup_v3_cfg(x, config_val, config_off=0x20):
    """bringup_v3 with the CONFIG write redirected to config_off."""
    bringup_v3(x)
    x.wr(x.OP + config_off, config_val)


def scan_events(x):
    """Scan the event page for chip-written events of ANY cycle state.
    The chip's event-ring cycle toggles on every ring wrap (the cc=5 storm
    wraps it constantly), so filtering on cycle==1 hides half the world.
    After a wipe, ANY nonzero slot is fresh."""
    out = []
    page = x.memck(x.EVTR, 0x1000)
    for k in range(256):
        param, status, control = struct.unpack_from("<QII", page, 16 * k)
        if control or status or param:
            typ = (control >> 10) & 0x3F
            cc = (status >> 24) & 0xFF
            slot = (control >> 24) & 0xFF
            out.append((k, typ, cc, slot, param, status, control))
    return out


def wipe_events(x):
    """Zero the event page and acknowledge with ERDP|EHB (bit 3): the chip
    requires the Event-Handler-Busy ack to keep servicing commands."""
    x.memwr(x.EVTR, b"\x00" * 0x1000)
    x.w64(x.RTS + 0x20 + 0x18, (x.DMA + x.EVTR) | 8)
    # clear any pending interrupt (IMAN.IP W1C) and keep IE
    x.wr(x.RTS + 0x20 + 0x00, 0x3)


def ack_events(x, offset=0x10):
    """Advance ERDP past `offset` bytes of consumed events, EHB set."""
    if offset is None:
        offset = 0x10
    x.w64(x.RTS + 0x20 + 0x18, (x.DMA + x.EVTR + offset) | 8)
    x.wr(x.RTS + 0x20 + 0x00, 0x3)


def enable_slot_try(x, wait=4.0):
    """Write the Enable Slot rung and wait for its completion."""
    wipe_events(x)
    x.memwr(LADDER, x.trb(0, 0, 9, 0))
    x.doorbell(0)
    t0 = time.time()
    seen = set()
    while time.time() - t0 < wait:
        for (k, typ, cc, slot, param, status, control) in scan_events(x):
            key = (k, param, status, control)
            if key in seen:
                continue
            seen.add(key)
            if typ == 33 and param in (x.DMA + LADDER, x.DMA + LADDER + 0x10):
                return cc, slot
        time.sleep(0.1)
    return None, None


def port_reset(x, port=2, wait_s=3.0):
    ps = x.portsc(port)
    if not (ps & 1):
        return False
    x.wr(x.OP + 0x400 + 0x10 * (port - 1), ps | 0x10)
    t0 = time.time()
    while time.time() - t0 < wait_s:
        cur = x.portsc(port)
        if not ((cur >> 4) & 1) and ((cur >> 5) & 0xF) == 0 and (cur & 1):
            return True
        time.sleep(0.01)
    return False
