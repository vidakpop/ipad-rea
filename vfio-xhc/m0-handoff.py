#!/usr/bin/env python3
"""m0-handoff.py — VFIO claim of the AMD Cezanne xHC (0000:04:00.3).

Milestone 0 of docs/vfio-xhc-plan.md:
  1. unbind from xhci_hcd -> bind vfio-pci (already done on this box)
  2. open container/group, SET_CONTAINER, SET_IOMMU(type1)
  3. open the per-device fd when available, VFIO_DEVICE_GET_INFO
  4. VFIO_DEVICE_GET_REGION_INFO(0) -> BAR0 size/offset
  5. mmap BAR0, dump xHC operational capability registers:
     CAPLENGTH, HCIVERSION, HCSPARAMS1/2, page size, MaxPorts, MaxSlots

Run with sudo. Idempotent.
"""
import ctypes, fcntl, mmap, os, struct, sys, time

BDF = "0000:04:00.3"
DRIVER_PATH = "/sys/bus/pci/drivers"
VENDOR_AMD = 0x1022
DEVICE_CEZANNE_USB = 0x1639

# ---- ioctl encoding (linux/vfio.h) ----
VFIO_TYPE = 0x3B   # ';'
VFIO_BASE = 100

def _IO(nr):
    return (VFIO_TYPE << 8) | nr
def _IOW(nr, sz):
    return (1 << 30) | ((sz & 0x3FFF) << 16) | (VFIO_TYPE << 8) | nr
def _IOWR(nr, sz):
    return (3 << 30) | ((sz & 0x3FFF) << 16) | (VFIO_TYPE << 8) | nr

VFIO_GET_API_VERSION        = _IO(VFIO_BASE + 0)
VFIO_CHECK_EXTENSION       = _IO(VFIO_BASE + 1)
VFIO_GROUP_SET_CONTAINER   = _IO(VFIO_BASE + 4)
VFIO_GROUP_UNSET_CONTAINER = _IO(VFIO_BASE + 5)
VFIO_SET_IOMMU             = _IO(VFIO_BASE + 10)
VFIO_DEVICE_GET_INFO       = _IOWR(VFIO_BASE + 16, 16)
VFIO_DEVICE_GET_REGION_INFO = _IOWR(VFIO_BASE + 17, 40)
VFIO_DEVICE_NUM_IRQS       = _IO(VFIO_BASE + 15)
VFIO_IOMMU_TYPE1 = 1


def readsys(path):
    return open(path).read().strip()


def discover_group():
    import glob
    for m in glob.glob('/sys/kernel/iommu_groups/*/devices/%s' % BDF):
        parts = m.split('/')
        if len(parts) >= 6 and parts[4].isdigit():
            return int(parts[4])
    return None


def unbind_and_bind():
    dp = "/sys/bus/pci/devices/%s/driver" % BDF
    cur = os.readlink(dp) if os.path.islink(dp) else None
    if cur and cur.endswith("vfio-pci"):
        print("[ok] already bound to vfio-pci")
        return
    if cur:
        print("[..] unbinding from %s" % cur.rsplit("/", 1)[1])
        with open("%s/unbind" % dp, "w") as f:
            f.write(BDF)
        time.sleep(1)
    if not os.path.exists("%s/vfio-pci" % DRIVER_PATH):
        print("[..] modprobe vfio-pci")
        os.system("modprobe vfio-pci")
        time.sleep(0.5)
    with open("%s/vfio-pci/new_id" % DRIVER_PATH, "w") as f:
        f.write("%04x %04x" % (VENDOR_AMD, DEVICE_CEZANNE_USB))
    time.sleep(1)
    cur = os.readlink(dp) if os.path.islink(dp) else None
    if not (cur and cur.endswith("vfio-pci")):
        print("[!!] bind failed; driver now: %s" % cur)


def open_device_fd():
    # newer kernels export /dev/vfio/devices/<bdf>
    p = "/dev/vfio/devices/%s" % BDF
    if os.path.exists(p):
        return os.open(p, os.O_RDWR)
    return None


def ioctl(fd, req, buf):
    return fcntl.ioctl(fd, req, buf, True)


def main():
    print("== m0: VFIO handoff of %s (AMD Cezanne xHC) ==" % BDF)
    print("device id: %s:%s" % (readsys("/sys/bus/pci/devices/%s/vendor" % BDF),
                                 readsys("/sys/bus/pci/devices/%s/device" % BDF)))
    group = discover_group()
    print("IOMMU group: %s" % group)
    if group is None:
        sys.exit("[!!] no IOMMU group")

    unbind_and_bind()

    cfd = os.open("/dev/vfio/vfio", os.O_RDWR)
    ver = fcntl.ioctl(cfd, VFIO_GET_API_VERSION)
    print("vfio api version: %s" % ver)
    ok = fcntl.ioctl(cfd, VFIO_CHECK_EXTENSION, VFIO_IOMMU_TYPE1)
    print("type1 iommu: %s" % ("yes" if ok else "NO"))
    if not ok:
        sys.exit(1)

    gfd = os.open("/dev/vfio/%d" % group, os.O_RDWR)
    fcntl.ioctl(gfd, VFIO_GROUP_SET_CONTAINER, struct.pack("i", cfd))
    fcntl.ioctl(cfd, VFIO_SET_IOMMU, struct.pack("I", VFIO_IOMMU_TYPE1))
    print("group attached to type1 container")

    dfd = open_device_fd()
    if dfd is None:
        sys.exit("[!!] no /dev/vfio/devices cdev on this kernel — "
                 "needs kernel >= 5.0 vfio_no_cdev off; report this")
    print("device fd: %s" % dfd)

    # VFIO_DEVICE_GET_INFO: struct {argsz, flags, num_regions, num_irqs}
    buf = bytearray(struct.pack("IIII", 16, 0, 0, 0))
    ioctl(dfd, VFIO_DEVICE_GET_INFO, buf)
    argsz, flags, num_regions, num_irqs = struct.unpack("IIII", buf)
    print("device info: flags=%#x regions=%d irqs=%d" % (flags, num_regions, num_irqs))

    # Region 0 = config/BARs
    # struct vfio_region_info { argsz, flags, index(u64), offset(u64), size(u64), cap_offset, reserved }
    ri = bytearray(struct.pack("IIQQQII", 40, 0, 0, 0, 0, 0, 0))
    # layout: argsz(4) flags(4) index(4+pad4? no: struct is
    #   u32 argsz; u32 flags; u64 index; ... with implicit pad after flags? Actually:
    #   argsz u32; flags u32; then u64 index naturally aligned at offset 8 — total 40.
    struct.pack_into("II", ri, 0, 40, 0)
    ioctl(dfd, VFIO_DEVICE_GET_REGION_INFO, ri)
    argsz, rflags = struct.unpack_from("II", ri, 0)
    index, offset, size = struct.unpack_from("QQQ", ri, 8)
    print("region0(BAR): flags=%#x offset=%#x size=%#x" % (rflags, offset, size))
    if not (rflags & 0x2):  # VFIO_REGION_INFO_FLAG_MMAP
        print("[!!] region0 not mmap-able")
        sys.exit(1)

    bar = mmap.mmap(dfd, size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE,
                    offset=offset)
    try:
        caplength = struct.unpack_from("<B", bar, 0x00)[0]
        hciversion = struct.unpack_from("<H", bar, 0x02)[0]
        hcsp1, hcsp2 = struct.unpack_from("<II", bar, 0x04)
        maxports = (hcsp1 >> 24) & 0xFF
        maxintr = (hcsp1 >> 8) & 0x3FF
        maxslots = hcsp2 & 0xFF
        pagesize = struct.unpack_from("<I", bar, caplength + 0x08)[0]
        print("[xHC] CAPLENGTH=%d HCIVERSION=%#x HCSPARAMS1=%#x HCSPARAMS2=%#x"
              % (caplength, hciversion, hcsp1, hcsp2))
        print("[xHC] MaxPorts=%d MaxIntrs=%d MaxSlots=%d PageSize=%#x"
              % (maxports, maxintr, maxslots, pagesize))
        # operational registers live at bar + caplength
        usbcmd = struct.unpack_from("<I", bar, caplength + 0x00)[0]
        usbsts = struct.unpack_from("<I", bar, caplength + 0x04)[0]
        print("[xHC] op@%#x: USBCMD=%#04x USBSTS=%#04x (HCHalted=%d)"
              % (caplength, usbcmd & 0xFFFF, usbsts & 0x1FF, (usbsts >> 0) & 1))
        print("M0 COMPLETE: controller is ours, caps readable.")
    finally:
        bar.close()


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("run with sudo")
    main()
