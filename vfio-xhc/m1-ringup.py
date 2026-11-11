#!/usr/bin/env python3
"""m1-ringup.py — userspace xHCI bring-up on the VFIO-claimed AMD Cezanne xHC.

Lessons encoded (from tonight's debugging):
  - ALL register access via pread/pwrite on the device fd (the mmapped-BAR
    write path does not stick on this platform; reads through mmap were fine
    but writes were swallowed).
  - No HCRST (it can wedge op writes on this AMD); rely on the kernel unbind
    having left the controller cleanly halted.
  - PCI BusMaster must be restored after the kernel's unbind quarantine.
  - iommufd IOAS maps use FIXED_IOVA with our own iova allocator, R|W flags.
  - Scratchpad count from HCSPARAMS2 (Hi/Lo combo); SPB written to CONFIG
    even though CONFIG read-back shows 0 - the device's ENABLE_SLOT verdict
    is the real test (AMD seems to lie on CONFIG reads).

Flow: bind iommufd -> attach PT -> restore BusMaster -> rings/scratchpads
mapped -> program DCBAAP/CRCR/ERST via pwrite -> RUN -> NOP -> poll events ->
ENABLE_SLOT -> print verdict.
Run with sudo.
"""
import ctypes
import ctypes.util
import fcntl
import glob
import os
import struct
import sys
import time

BDF = "0000:04:00.3"

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                      ctypes.c_int, ctypes.c_int, ctypes.c_long]
PROT_RW = 0x1 | 0x2
MAP_SHARED_ANON = 0x01 | 0x20


def dma_alloc(size):
    size = (size + 4095) & ~4095
    addr = libc.mmap(None, size, PROT_RW, MAP_SHARED_ANON, -1, 0)
    if addr in (0, -1, 2**64 - 1):
        raise OSError("mmap failed: %d" % addr)
    return addr, size


def poke(addr, data, off=0):
    ctypes.memmove(ctypes.c_void_p(addr + off), data, len(data))


def peek(addr, off, length):
    buf = ctypes.create_string_buffer(length)
    ctypes.memmove(buf, ctypes.c_void_p(addr + off), length)
    return bytes(buf)


def _IO(nr):
    return ((0x3B << 8) | nr)

VFIO_DEVICE_GET_INFO          = _IO(100 + 7)
VFIO_DEVICE_GET_REGION_INFO   = _IO(100 + 8)
VFIO_DEVICE_BIND_IOMMUFD      = _IO(100 + 18)
VFIO_DEVICE_ATTACH_IOMMUFD_PT = _IO(100 + 19)
IOMMU_IOAS_ALLOC = _IO(0x81)
IOMMU_IOAS_MAP   = _IO(0x85)

IOVA_NEXT = [0x100000]


def ioas_alloc(iommufd):
    buf = bytearray(struct.pack("<III", 12, 0, 0))
    fcntl.ioctl(iommufd, IOMMU_IOAS_ALLOC, buf, True)
    return struct.unpack_from("<I", buf, 8)[0]


def ioas_map(iommufd, ioas_id, user_va, length):
    flags = (1 << 0) | (1 << 1) | (1 << 2)   # FIXED | WRITEABLE | READABLE
    iova = IOVA_NEXT[0]
    IOVA_NEXT[0] = (IOVA_NEXT[0] + 0x1000 + length - 1) & ~0xFFF
    buf = bytearray(struct.pack("<IIIIQQQ", 40, flags, ioas_id, 0,
                                user_va, length, iova))
    try:
        fcntl.ioctl(iommufd, IOMMU_IOAS_MAP, buf, True)
    except OSError as e:
        raise OSError("ioas_map(va=%#x len=%#x iova=%#x) failed: %s"
                      % (user_va, length, iova, e))
    return iova


class XHC:
    """Register access strictly via pread/pwrite on the device fd."""

    def __init__(self, dfd, roff):
        self.dfd = dfd
        self.roff = roff
        self.caplength = self.r32(0x00) & 0xFF
        self.hciversion = self.r16(0x02)
        self.hcs1 = self.r32(0x04)
        self.hcs2 = self.r32(0x08)
        self.hccparams = self.r32(0x10)
        self.dboff = self.r32(0x14)
        self.rtsoff = self.r32(0x18)
        self.maxports = (self.hcs1 >> 24) & 0xFF
        self.maxintrs = (self.hcs1 >> 8) & 0x3FF
        self.maxslots = self.hcs1 & 0xFF
        lo = (self.hcs2 >> 16) & 0x3FF
        hi = (self.hcs2 >> 27) & 0x1F
        self.scratch = lo + (hi << 5)
        self.ac64 = self.hccparams & 1
        self.op = self.caplength

    def rd(self, off, n=4):
        return os.pread(self.dfd, n, self.roff + off)

    def r32(self, off):
        return struct.unpack("<I", self.rd(off, 4))[0]

    def r16(self, off):
        return struct.unpack("<H", self.rd(off, 2))[0]

    def w32(self, off, val):
        os.pwrite(self.dfd, struct.pack("<I", val & 0xFFFFFFFF),
                  self.roff + off)

    def w64(self, off, val):
        self.w32(off, val & 0xFFFFFFFF)
        self.w32(off + 4, (val >> 32) & 0xFFFFFFFF)

    def usbcmd(self, val=None):
        if val is None:
            return self.r32(self.op + 0x00)
        self.w32(self.op + 0x00, val)

    def usbsts(self):
        return self.r32(self.op + 0x04)

    def doorbell(self, slot, val):
        self.w32(self.dboff + 4 * slot, val)

    def irq0(self, off):
        return self.r32(self.rtsoff + 0x20 + off)

    def irq0_w(self, off, val):
        self.w32(self.rtsoff + 0x20 + off, val)


TRB_CMD_COMPLETION = 33
TRB_PORT_STATUS   = 34
TRB_TRANSFER      = 32


def main():
    print("== m1: xHCI ring-up (pwrite register path) ==")
    ifd = os.open("/dev/iommu", os.O_RDWR)
    ioas = ioas_alloc(ifd)
    print("ioas_id=%d" % ioas)

    dfd = os.open(os.environ.get("XDC_CDEV", sorted(glob.glob("/dev/vfio/devices/vfio*"))[0]), os.O_RDWR)
    fcntl.ioctl(dfd, VFIO_DEVICE_BIND_IOMMUFD,
                bytearray(struct.pack("<IIiIQ", 24, 0, ifd, 0, 0)), True)
    print("bound")
    fcntl.ioctl(dfd, VFIO_DEVICE_ATTACH_IOMMUFD_PT,
                bytearray(struct.pack("<IIII", 16, 0, ioas, 0)), True)
    print("attached to ioas")

    # region info: 0 = MMIO BAR, 7 = config
    rbar = bytearray(struct.pack("IIIIQQ", 32, 0, 0, 0, 0, 0))
    fcntl.ioctl(dfd, VFIO_DEVICE_GET_REGION_INFO, rbar, True)
    roff = struct.unpack_from("<QQ", rbar, 16)[1]
    rcfg = bytearray(struct.pack("IIIIQQ", 32, 0, 7, 0, 0, 0))
    fcntl.ioctl(dfd, VFIO_DEVICE_GET_REGION_INFO, rcfg, True)
    cfoff = struct.unpack_from("<QQ", rcfg, 16)[1]

    # BusMaster restore (kernel clears it on unbind)
    cmd = struct.unpack("<H", os.pread(dfd, 2, cfoff + 4))[0]
    os.pwrite(dfd, struct.pack("<H", cmd | 0x4), cfoff + 4)
    print("PCI cmd=%#x" % struct.unpack("<H", os.pread(dfd, 2, cfoff + 4))[0])

    x = XHC(dfd, roff)
    print("xHC: caplen=%d ver=%#x ports=%d intrs=%d slots=%d scratch=%d ac64=%d "
          "dboff=%#x rtsoff=%#x"
          % (x.caplength, x.hciversion, x.maxports, x.maxintrs, x.maxslots,
             x.scratch, x.ac64, x.dboff, x.rtsoff))

    # ensure halted + clear any latched error bits
    x.usbcmd(0)
    t0 = time.time()
    while not (x.usbsts() & 1):
        if time.time() - t0 > 3:
            print("[!!] controller won't halt (sts=%#x cmd=%#x)"
                  % (x.usbsts(), x.usbcmd()))
            sys.exit(1)
        time.sleep(0.02)
    sts = x.usbsts()
    if sts & 0x1010:
        x.w32(x.op + 0x04, sts)          # clear HCE/SRE
        time.sleep(0.05)
    print("halted clean: USBSTS=%#x" % x.usbsts())

    # ---- DMA memory ----
    regions = {}

    def region(name, nbytes):
        addr, alen = dma_alloc(nbytes)
        iova = ioas_map(ifd, ioas, addr, alen)
        ctypes.memset(ctypes.c_void_p(addr), 0, alen)
        regions[name] = (addr, iova)
        print("  %-10s iova=%#x" % (name, iova))
        return addr, iova

    dcbaa_a, dcbaa_iova = region("dcbaa", 4096)
    scratch = x.scratch
    sp_arr_a, sp_arr_iova = (0, 0)
    sp_pages = []
    if scratch > 0:
        sp_arr_a, sp_arr_iova = region("sp-arr", 4096)
        for i in range(scratch):
            pa, piova = region("sp-%d" % i, 4096)
            sp_pages.append(piova)
    cmd_a, cmd_iova = region("cmd-ring", 4096)
    ev_a, ev_iova = region("ev-ring", 4096)
    erst_a, erst_iova = region("erst", 4096)
    n_trb = 4096 // 16

    # scratchpad array contents
    for i, piova in enumerate(sp_pages):
        poke(sp_arr_a, struct.pack("<Q", piova), off=i * 8)
    poop = 0
    if scratch > 0:
        poke(dcbaa_a, struct.pack("<Q", sp_arr_iova))

    # ERST entry: {u64 seg_addr; u32 seg_size; u32 rsvd}
    poke(erst_a, struct.pack("<QII", ev_iova, n_trb, 0))

    # ring link TRBs (LINK type=6, TC=1) at the last slot of each ring
    for table, ring_iova in ((cmd_a, cmd_iova), (ev_a, ev_iova)):
        ctl = 1 | (1 << 1) | (6 << 10)
        poke(table, struct.pack("<QII", ring_iova, 0, ctl),
             off=(n_trb - 1) * 16)

    # ---- program via pwrite ----
    # DCBAAP/CRCR/CONFIG are only writable while HALTED (xHCI spec):
    # a previous run may have left the controller running.
    x.usbcmd(0)
    t0 = time.time()
    while not x.usbsts() & 1:
        if time.time() - t0 > 2:
            print("[!!] controller refuses to halt: USBSTS=%#x" % x.usbsts())
            sys.exit(1)
        time.sleep(0.01)
    print("controller halted (USBSTS=%#x)" % x.usbsts())
    x.w32(x.op + 0x20, x.maxslots | (min(scratch, 0x7F) << 25))   # CONFIG
    x.w64(x.op + 0x18, dcbaa_iova)                                # DCBAAP
    x.w64(x.op + 0x10, cmd_iova)                                  # CRCR: pointer only (CRR=0!)
    x.irq0_w(0x08, 1)                      # ERSTSZ
    x.irq0_w(0x10, erst_iova & 0xFFFFFFFF)
    x.irq0_w(0x14, erst_iova >> 32)
    erdp = ev_iova | (1 << 3)
    x.irq0_w(0x18, erdp & 0xFFFFFFFF)
    x.irq0_w(0x1C, erdp >> 32)
    print("programmed (CONFIG read-back=%#x — trusting the device verdict)"
          % x.r32(x.op + 0x20))

    # ---- run ----
    x.usbcmd(1)
    t0 = time.time()
    ok_run = False
    while time.time() - t0 < 2:
        s = x.usbsts()
        if (s & 1) == 0:
            ok_run = True
            break
        if s & 0x1000:
            print("[!!] HCE while starting; USBSTS=%#x" % s)
            break
        time.sleep(0.02)
    if not ok_run:
        print("[!!] did not run: USBCMD=%#x USBSTS=%#x" % (x.usbcmd(), x.usbsts()))
        sys.exit(1)
    print("controller RUNNING (USBSTS=%#x)" % x.usbsts())

    # ---- enqueue NOP TRB at cmd ring[0], cycle=1; ring doorbell 0 ----
    nop_ctl = (1 << 0) | (12 << 10)
    poke(cmd_a, struct.pack("<QII", 0, 0, nop_ctl), off=0)
    x.doorbell(0, 0)
    print("NOP armed + doorbell")
    t0 = time.time()
    while time.time() - t0 < 0.3:
        crr = x.r32(x.op + 0x10) | (x.r32(x.op + 0x14) << 32)
        if crr & 1:
            print("[ok] CRCR.CRR self-set to 1 -> xHC FETCHED the ring! CRCR=%#x" % crr)
            break
        time.sleep(0.005)
    else:
        dcbaap = x.r32(x.op + 0x18) | (x.r32(x.op + 0x1C) << 32)
        print("[..] CRCR unchanged after doorbell; CRCR=%#x DCBAAP=%#x CONFIG=%#x"
              % (crr, dcbaap, x.r32(x.op + 0x20)))

    ev_idx = [0]

    def wait_event(timeout=2.0):
        t0 = time.time()
        while time.time() - t0 < timeout:
            trb = peek(ev_a, ev_idx[0] * 16, 16)
            param, status, control = struct.unpack("<QII", trb)
            if control & 1:
                ev_idx[0] += 1
                n = ev_iova + (ev_idx[0] * 16)
                x.irq0_w(0x18, (n | (1 << 3)) & 0xFFFFFFFF)
                x.irq0_w(0x1C, ((n | (1 << 3)) >> 32) & 0xFFFFFFFF)
                typ = (control >> 10) & 0x3F
                cc = (status >> 24) & 0xFF
                slot = (control >> 24) & 0xFF
                return typ, cc, slot, param
            time.sleep(0.002)
        return None

    ev = wait_event()
    if ev is None:
        print("[!!] no event for NOP; cmd ring first TRB dump:",
              peek(cmd_a, 0, 16).hex())
        print("    event ring first TRB:", peek(ev_a, 0, 16).hex())
        x.usbcmd(0)
        sys.exit(1)
    typ, cc, slot, param = ev
    print("EVENT: type=%d completion=%#x slot=%d param=%#x" % (typ, cc, slot, param))
    if typ != TRB_CMD_COMPLETION:
        print("[!!] expected command-completion (33)")
        x.usbcmd(0)
        sys.exit(1)
    print("M1 CORE OK: NOP completed through our userspace rings.")

    # ---- ENABLE_SLOT: the verdict on CONFIG.MaxSlotsEnabled ----
    # command TRB parameter = slot-type (0 = default speed)
    en_ctl = (1 << 0) | (9 << 10)
    poke(cmd_a, struct.pack("<QII", 0, 0, en_ctl), off=16)
    x.doorbell(0, 0)
    ev = wait_event()
    if ev is None:
        print("[!!] no slot event")
        x.usbcmd(0)
        sys.exit(1)
    typ, cc, slot, param = ev
    print("ENABLE_SLOT verdict: type=%d completion=%#x slot=%d" % (typ, cc, slot))
    if cc == 1:
        print(">>> CONFIG truly took effect — slot reserved. M1 COMPLETE!")
    elif cc == 0x0B:
        print(">>> slots-disabled verdict: CONFIG writes really are ignored")
    x.usbcmd(0)
    print("done (controller halted again)")
    return 0


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("run with sudo")
    sys.exit(main())
