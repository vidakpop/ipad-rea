#!/usr/bin/env python3
"""m0-handoff.py — VFIO claim of the Renesas uPD720202 (0000:02:00.0).

Milestone 0 of docs/vfio-xhc-plan.md:
  1. unbind from xhci-pci-renesas (the webcam's bus dies — harmless)
  2. bind vfio-pci
  3. open /dev/vfio/10, mmap BAR0
  4. read xHC operational registers (CAPLENGTH, HCSPARAMS, page size)
  5. halt+reset the HC through USBCMD, verify it comes back

Run with sudo. Idempotent: safe to re-run.
"""
import ctypes, fcntl, mmap, os, struct, sys, time

BDF = "0000:02:00.0"
DRIVER_PATH = "/sys/bus/pci/drivers"
VENDOR_RENESAS = 0x1912
DEVICE_UPD720202 = 0x0015
GROUP = None  # discovered

VFIO_TYPE = ord('V') << 8
VFIO_BASE = 0x100
VFIO_GET_API_VERSION = VFIO_BASE + 0
VFIO_CHECK_EXTENSION = VFIO_BASE + 1
VFIO_GROUP_SET_CONTAINER = VFIO_BASE + 4
VFIO_UNSET_CONTAINER = VFIO_BASE + 5
VFIO_SET_IOMMU = VFIO_BASE + 6
VFIO_IOMMU_TYPE1 = 1

VFIO_DEVICE_GET_INFO = VFIO_BASE + 7          # _IOWR('V', 0x27, vfio_device_info)
VFIO_DEVICE_GET_REGION_INFO = VFIO_BASE + 8   # _IOWR(...)

def read(path):
    return open(path).read().strip()

def discover():
    bdf_short = BDF + ""
    for line in os.popen("ls /sys/kernel/iommu_groups/*/devices/%s 2>/dev/null" % BDF):
        g = line.strip().split("/")[4]
        return int(g)
    return None

def unbind_and_bind():
    cur = read("/sys/bus/pci/devices/%s/driver" % BDF) if os.path.exists("/sys/bus/pci/devices/%s/driver" % BDF) else None
    if cur and cur.endswith("vfio-pci"):
        print("[ok] already bound to vfio-pci")
        return
    if cur:
        print("[..] unbinding from %s" % cur.rsplit("/", 1)[1])
        with open("/sys/bus/pci/devices/%s/driver/unbind" % BDF, "w") as f:
            f.write(BDF)
        time.sleep(1)
    # ensure vfio-pci knows the device
    with open("%s/vfio-pci/new_id" % DRIVER_PATH, "w") as f:
        f.write("%04x %04x" % (VENDOR_RENESAS, DEVICE_UPD720202))
    time.sleep(1)
    d = read("/sys/bus/pci/devices/%s/driver" % BDF) if os.path.exists("/sys/bus/pci/devices/%s/driver" % BDF) else None
    if not (d and d.endswith("vfio-pci")):
        print("[!!] bind failed; driver now: %s" % d)

def vfio_open(group):
    gfd = os.open("/dev/vfio/%d" % group, os.O_RDWR)
    fcntl.ioctl(gfd, VFIO_GROUP_SET_CONTAINER, struct.pack("I", gfd) if False else None)  # placeholder
    return gfd

def main():
    global GROUP
    print("== m0: VFIO handoff of %s (Renesas uPD720202) ==" % BDF)
    ven = read("/sys/bus/pci/devices/%s/vendor" % BDF)
    dev = read("/sys/bus/pci/devices/%s/device" % BDF)
    print("device id: %s:%s" % (ven, dev))
    GROUP = discover()
    print("IOMMU group: %s" % GROUP)
    if GROUP is None:
        sys.exit("[!!] no IOMMU group — enable AMD-Vi in BIOS")

    unbind_and_bind()

    cfd = os.open("/dev/vfio/vfio", os.O_RDWR)
    ver = fcntl.ioctl(cfd, VFIO_GET_API_VERSION)
    print("vfio api version: %d" % ver)
    ok = fcntl.ioctl(cfd, VFIO_CHECK_EXTENSION, VFIO_IOMMU_TYPE1)
    print("type1 iommu support: %s" % ("yes" if ok else "NO"))
    if not ok:
        sys.exit(1)

    gfd = os.open("/dev/vfio/%d" % GROUP, os.O_RDWR)
    # VFIO_GROUP_SET_CONTAINER: pointer to the container fd
    fcntl.ioctl(gfd, VFIO_GROUP_SET_CONTAINER, struct.pack("i", cfd))
    fcntl.ioctl(cfd, VFIO_SET_IOMMU, struct.pack("I", VFIO_IOMMU_TYPE1))
    print("group %d attached to type1 container" % GROUP)

    # VFIO_DEVICE_GET_INFO
    dev_path = "/dev/vfio/devices/%s" % BDF
    try:
        dfd = os.open(dev_path, os.O_RDWR)
        print("device fd opens (vfio/devices path)")
    except FileNotFoundError:
        # cdev path only on newer kernels; fall back to group-relative ioctl
        dfd = None
        print("[note] no per-device cdev; using group fd for device ioctls")

    # GET_INFO via ioctl on the group fd using vfio_device_info struct:
    # struct vfio_device_info { __u32 argsz; __u32 flags; __u32 num_regions; __u32 num_irqs; }
    info = struct.pack("IIII", 16, 0, 0, 0)
    try:
        hdr = bytearray(info)
        import array
        buf = array.array('b', b"\0" * 16)
        struct.pack_into("IIII", buf, 0, 16, 0, 0, 0)
        info = fcntl.ioctl(dfd if dfd is not None else gfd, VFIO_DEVICE_GET_INFO, buf, True)
        argsz, flags, num_regions, num_irqs = struct.unpack("IIII", info)
        print("device info: flags=%#x regions=%d irqs=%d" % (flags, num_regions, num_irqs))
    except OSError as e:
        print("[!!] GET_INFO failed (need per-device fd on this kernel?): %s" % e)

    # Region 0 = BAR0 config. Map and read xHC caps.
    # For type1 with group fd: VFIO_DEVICE_GET_REGION_INFO on the cdev fd.
    print("[m0 core next: region info + BAR0 mmap + HCSPARAMS dump]")

if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("run with sudo")
    main()
