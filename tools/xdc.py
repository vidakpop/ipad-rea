#!/usr/bin/env python3
"""xdc — userspace xHCI host driver for the AMD FCH xDC (04:00.4) via the xdcdrv kernel module.

M1 (Nov 12 early am): command ring EXECUTES from python (NOP consumed), event ring
DELIVERS chip-written events (type-34 PortStatusChange seen, cc=1). All ring memory is
kernel dma_alloc_coherent ("borrowed" orphan-domain DMA pool); registers via module ioremap.

ioctl ABI (module): REG r/w 8B {off,val}; MEM r/w {off,len,val[64]}; IRQ_SETUP/COUNT (raw _IO).
Pool layout (fixed): DCBAA@0x0 SPARR@0x1000 SPpages@0x2000..0x42000 CMDR@0x42000 EVTR@0x43000
ERST@0x44000 CTX/scratch@0x45000.. — chip sees these at DMA_BASE plus offsets.
"""
import ctypes, os, struct, time

_IOC_NRBITS = 8
_MAGIC = 0xd6

def _ioc(d, n, sz): return (d << 30) | (sz << 16) | (_MAGIC << 8) | n

REG_READ  = _ioc(3, 1, 8)
REG_WRITE = _ioc(1, 2, 8)
MEM_READ  = _ioc(3, 3, 264)
MEM_WRITE = _ioc(1, 4, 264)
IRQ_SETUP = (_MAGIC << 8) | 5
IRQ_COUNT = (_MAGIC << 8) | 6

class Req(ctypes.Structure):
    _fields_ = [("off", ctypes.c_uint32), ("val", ctypes.c_uint32)]

class MemReq(ctypes.Structure):
    _fields_ = [("off", ctypes.c_uint32), ("len", ctypes.c_uint32), ("val", ctypes.c_uint32 * 64)]

TRB_TYPES = {32: "TRANSFER", 33: "CMD_COMPLETION", 34: "PORT_STATUS", 36: "STREAM", 37: "MFWR"}

class Xdc:
    def __init__(self, dev="/dev/xdcdrv", dma=0xcc780000):
        self.fd = os.open(dev, os.O_RDWR)
        self.libc = ctypes.CDLL("libc.so.6", use_errno=True)
        self.DMA = dma
        self.POLL_US = 10000
        # pool layout
        self.DCBAA, self.SPARR, self.SPPG = 0x0000, 0x1000, 0x2000
        self.CMDR, self.EVTR, self.ERST = 0x42000, 0x43000, 0x44000
        self.CTX = 0x45000
        self.OP = self.rd(0) & 0xFF
        self.DBOFF = self.rd(0x14)
        self.RTS = self.rd(0x18)
        hcs1, self.hcs2 = self.rd(4), self.rd(8)
        self.maxslots = hcs1 & 0xFF
        self.maxports = (hcs1 >> 24) & 0xFF
        self.scratch = ((self.hcs2 >> 16) & 0x3FF) + (((self.hcs2 >> 27) & 0x1F) << 5)

    # ---- register / memory primitives ----
    def rd(self, off):
        r = Req(off, 0)
        if self.libc.ioctl(self.fd, REG_READ, ctypes.byref(r)) != 0:
            raise OSError(ctypes.get_errno())
        return r.val

    def wr(self, off, val):
        r = Req(off, val)
        if self.libc.ioctl(self.fd, REG_WRITE, ctypes.byref(r)) != 0:
            raise OSError(ctypes.get_errno())

    def r64(self, off):  return self.rd(off) | (self.rd(off + 4) << 32)
    def w64(self, off, v): self.wr(off, v & 0xFFFFFFFF); self.wr(off + 4, (v >> 32) & 0xFFFFFFFF)

    def memck(self, off, n):
        out = b""
        while len(out) < n:
            take = min(256, n - len(out))
            m = MemReq(off + len(out), take, (ctypes.c_uint32 * 64)())
            if self.libc.ioctl(self.fd, MEM_READ, ctypes.byref(m)) != 0:
                raise OSError(ctypes.get_errno())
            out += (ctypes.c_char * 256).from_buffer_copy(m.val).raw[:take]
        return out

    def memwr(self, off, data):
        d = data + b"\x00" * ((-len(data)) % 4)
        c = 0
        while c < len(d):
            chunk = d[c:c + 256]
            m = MemReq(off + c, len(chunk), (ctypes.c_uint32 * 64)())
            (ctypes.c_char * 256).from_buffer(m.val)[:len(chunk)] = chunk
            if self.libc.ioctl(self.fd, MEM_WRITE, ctypes.byref(m)) != 0:
                raise OSError(ctypes.get_errno())
            c += len(chunk)

    # ---- xHCI helpers ----
    def trb(self, param, status, typ, cycle, ctl_bits=0, slot=0):
        ctl = (cycle & 1) | (typ << 10) | ctl_bits | ((slot & 0xFF) << 24)
        return struct.pack("<QII", param & 0xFFFFFFFFFFFFFFFF, status & 0xFFFFFFFF, ctl)

    def hcrst(self):
        self.wr(self.OP + 0, 0x2)
        t0 = time.time()
        while time.time() - t0 < 3:
            if not self.rd(self.OP + 0) & 2 and not self.rd(self.OP + 4) & 4:
                return True
            time.sleep(0.01)
        return False

    def halt(self, timeout=2):
        self.wr(self.OP + 0, 0)
        t0 = time.time()
        while not self.rd(self.OP + 4) & 1:
            if time.time() - t0 > timeout: return False
            time.sleep(0.005)
        return True

    def run(self):
        self.wr(self.OP + 0, 1)
        time.sleep(0.05)
        return not self.rd(self.OP + 4) & 1

    def doorbell(self, slot=0, target=0):
        self.wr(self.DBOFF + 4 * slot, target)

    def arm_irq(self):
        self.libc.ioctl(self.fd, IRQ_SETUP)

    def irq_count(self):
        return self.libc.ioctl(self.fd, IRQ_COUNT)

    def bringup(self):
        """Full cold bring-up: HCRST -> halt -> rings -> registers -> RUN. NOP left to caller."""
        assert self.hcrst(), "HCRST failed"
        assert self.halt(), "halt failed"
        D = self.DMA
        memwr = self.memwr
        memwr(self.SPARR, b"".join(struct.pack("<Q", D + self.SPPG + i * 0x1000) for i in range(self.scratch)))
        memwr(self.DCBAA, struct.pack("<Q", D + self.SPARR) + b"\x00" * (512 - 8))
        memwr(self.CMDR, struct.pack("<QII", 0, 0, 1 | (12 << 10)))  # NOP TRB (armed)
        memwr(self.CMDR + 255*16, struct.pack("<QII", D + self.CMDR, 0, 1 | (1 << 1) | (6 << 10)))
        memwr(self.EVTR, b"\x00" * 0x1000)
        memwr(self.EVTR + 255*16, struct.pack("<QII", D + self.EVTR, 0, (1 << 1) | (6 << 10)))
        memwr(self.ERST, struct.pack("<QII", D + self.EVTR, 256, 0))
        self.wr(self.OP + 0x20, self.maxslots | (min(self.scratch, 0x7F) << 25))
        self.w64(self.OP + 0x18, D + self.DCBAA)   # DCBAAP
        self.w64(self.OP + 0x10, D + self.CMDR)    # CRCR (pointer only, CRR=0!)
        self.wr(self.RTS + 0x20 + 0x08, 1)         # ERSTSZ=1
        self.w64(self.RTS + 0x20 + 0x10, D + self.ERST)
        self.w64(self.RTS + 0x20 + 0x18, D + self.EVTR)
        self.wr(self.RTS + 0x20 + 0x00, 0x2)       # IMAN: IE
        assert self.run(), "controller did not run"

    # ---- event polling ----
    def wait_event(self, timeout=3.0):
        """Poll the event ring; retire events by advancing ERDP. Returns list of (type, cc, slot, param, status, control)."""
        t0 = time.time()
        while time.time() - t0 < timeout:
            page = self.memck(self.EVTR, 64)
            for k in range(4):
                param, status, control = struct.unpack_from("<QII", page, 16 * k)
                if control & 1:
                    nxt = self.EVTR + (k + 1) * 16
                    self.w64(self.RTS + 0x20 + 0x18, self.DMA + nxt)
                    return ((control >> 10) & 0x3F, (status >> 24) & 0xFF,
                            (control >> 24) & 0xFF, param, status, control)
            time.sleep(0.01)
        return None

    def portsc(self, port): return self.rd(self.OP + 0x400 + 0x10 * (port - 1))

    def events_clear(self):
        self.memwr(self.EVTR, b"\x00" * 0x1000)
        self.w64(self.RTS + 0x20 + 0x18, self.DMA + self.EVTR)

def main():
    import sys
    x = Xdc(dma=int(sys.argv[1], 16) if len(sys.argv) > 1 else 0xcc780000)
    print("OP=%d slots=%d ports=%d scratch=%d DB=%#x RTS=%#x" %
          (x.OP, x.maxslots, x.maxports, x.scratch, x.DBOFF, x.RTS))
    x.arm_irq()
    x.bringup()
    print("controller running; doorbell NOP...")
    x.doorbell(0)
    ev = x.wait_event()
    while ev:
        typ, cc, slot, param, status, control = ev
        print("EVENT type=%d(%s) cc=%d slot=%d param=%#x" %
              (typ, TRB_TYPES.get(typ, "?"), cc, slot, param))
        if typ == 33 and cc == 1:
            print(">>> command completion success — M1 FULLY VERIFIED")
            break
        ev = x.wait_event(timeout=1.0)
    x.halt()

if __name__ == "__main__":
    main()
