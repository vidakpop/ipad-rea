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

# values verified against /usr/include/linux/vfio.h on THIS kernel
VFIO_GET_API_VERSION        = _IO(VFIO_BASE + 0)
VFIO_CHECK_EXTENSION       = _IO(VFIO_BASE + 1)
VFIO_SET_IOMMU             = _IO(VFIO_BASE + 2)   # !!! +2 on modern headers
VFIO_GROUP_SET_CONTAINER   = _IO(VFIO_BASE + 4)
VFIO_GROUP_UNSET_CONTAINER = _IO(VFIO_BASE + 5)
VFIO_GROUP_GET_DEVICE_FD   = _IO(VFIO_BASE + 6)   # arg = ptr to name, returns fd
VFIO_DEVICE_GET_INFO       = _IO(VFIO_BASE + 7)
VFIO_DEVICE_GET_REGION_INFO = _IO(VFIO_BASE + 8)
VFIO_DEVICE_BIND_IOMMUFD   = _IO(VFIO_BASE + 18)
VFIO_DEVICE_ATTACH_IOMMUFD_PT = _IO(VFIO_BASE + 19)
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

    # Legacy container (type1) is dead on this kernel (iommufd era) — the
    # group->container attach is only needed to claim the group exclusively;
    # BAR mmap works through the device fd regardless. Defer DMA concerns to M1.
    # iommufd era ONLY: do not touch the legacy group/container (claiming the
    # group makes the cdev BIND_IOMMUFD fail with EBUSY — they are exclusive).
    print("[note] skipping legacy group/container claim (iommufd path)")

    # iommufd era: cdev fd -> BIND_IOMMUFD -> ioctls unlocked
    try:
        ifd = os.open("/dev/iommu", os.O_RDWR)
        print("iommufd: %d" % ifd)
    except OSError as e:
        sys.exit("[!!] open /dev/iommufd failed: %s" % e)
    import glob as _glob
    cdevs = sorted(_glob.glob("/dev/vfio/devices/vfio*"))
    if not cdevs:
        sys.exit("[!!] no /dev/vfio/devices cdev")
    dfd = os.open(cdevs[0], os.O_RDWR)
    print("cdev: %s fd=%d" % (cdevs[0], dfd))
    # struct vfio_device_bind_iommufd {argsz, flags, iommufd(s32), out_devid, token_ptr(u64)}
    bind = bytearray(struct.pack("<IIiIQ", 24, 0, ifd, 0, 0))
    ioctl(dfd, VFIO_DEVICE_BIND_IOMMUFD, bind)
    devid = struct.unpack_from("<I", bind, 8)[0]
    print("bound to iommufd: devid=%d" % devid)

    # struct vfio_device_info {argsz, flags, num_regions, num_irqs, cap_offset, pad}
    buf = bytearray(struct.pack("IIIIII", 24, 0, 0, 0, 0, 0))
    ioctl(dfd, VFIO_DEVICE_GET_INFO, buf)
    argsz, flags, num_regions, num_irqs, capo, pad = struct.unpack("IIIIII", buf[:24])
    print("device info: flags=%#x regions=%d irqs=%d" % (flags, num_regions, num_irqs))

    # struct vfio_region_info { u32 argsz, flags, index, cap_offset, u64 size, u64 offset }
    ri = bytearray(struct.pack("IIIIQQ", 32, 0, 0, 0, 0, 0))
    ioctl(dfd, VFIO_DEVICE_GET_REGION_INFO, ri)
    argsz, rflags, rindex, capoff = struct.unpack_from("IIII", ri, 0)
    size, offset = struct.unpack_from("QQ", ri, 16)
    print("region0(BAR): flags=%#x index=%d offset=%#x size=%#x" % (rflags, rindex, offset, size))
    if not (rflags & 0x4):  # VFIO_REGION_INFO_FLAG_MMAP
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
