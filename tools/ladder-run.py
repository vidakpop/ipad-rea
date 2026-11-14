#!/usr/bin/env python3
"""Ladder runner: push one complete TD + kernel-serve fetch kick.

Per shape:
  state/ring snapshot -> PUSH the shape -c0.5s..0-> tiny usbfs serve
  (kernel URB = its own doorbell kicks the xHC fetch engine; the kernel
  DMAs into its OWN buffer, never into module staging) -> settle ->
  state/ring + staging readback (IN shapes) -> second serve as a
  health probe -> verdict.

Evidence classes:
  - WARN event (dmesg count before/after) = a module TD executed
  - staging signature = what the ROM put on the wire for OUR TD
  - serve health post-shape = ROM alive and answering
Safe classes only: complete TDs, kernel URBs, zero cancels, zero resets.
"""
import argparse
import ctypes
import fcntl
import glob
import os
import re
import struct
import subprocess
import sys
import time

NDUMP = 48
RD_SIZE = 6 * 4 + NDUMP * 4 * 4 + 1024
ST_SIZE = 40
RB_SIZE = 8 + 4096
IOC_PUSH = (1 << 30) | (32 << 16) | (ord("R") << 8) | 1
IOC_STATE = (2 << 30) | (ST_SIZE << 16) | (ord("R") << 8) | 3
IOC_RINGDUMP = (2 << 30) | (RD_SIZE << 16) | (ord("R") << 8) | 6
IOC_READBACK = (3 << 30) | (RB_SIZE << 16) | (ord("R") << 8) | 7
USBDEVFS_CONTROL = (3 << 30) | (24 << 16) | (0x55 << 8) | 0


class CtrlTransfer(ctypes.Structure):
    _fields_ = [("bRequestType", ctypes.c_ubyte), ("bRequest", ctypes.c_ubyte),
                ("wValue", ctypes.c_ushort), ("wIndex", ctypes.c_ushort),
                ("wLength", ctypes.c_ushort), ("timeout", ctypes.c_uint),
                ("data", ctypes.c_void_p)]


def find_dev():
    for p in glob.glob("/sys/bus/usb/devices/*/idProduct"):
        if open(p).read().strip() == "1227":
            n = os.path.dirname(p)
            return int(open(n + "/busnum").read()), int(open(n + "/devnum").read())
    return None, None


def serve(want=182, timeout=2000):
    """Tiny kernel control URB. Returns (ret, bytes, ms)."""
    bus, dev = find_dev()
    if not bus:
        return None, b"", 0
    fd = os.open("/dev/bus/usb/%03d/%03d" % (bus, dev), os.O_RDWR)
    buf = ctypes.create_string_buffer(255)
    ct = CtrlTransfer(0x80, 6, 0x0303, 0x0409, want, timeout,
                      ctypes.cast(buf, ctypes.c_void_p))
    t0 = time.time()
    try:
        n = fcntl.ioctl(fd, USBDEVFS_CONTROL, ct)
        return n, buf.raw[:max(0, n)], (time.time() - t0) * 1000
    except OSError as e:
        return -e.errno, b"", (time.time() - t0) * 1000
    finally:
        os.close(fd)


def state(rfd):
    buf = bytearray(ST_SIZE)
    fcntl.ioctl(rfd, IOC_STATE, buf, True)
    f = struct.unpack("<QIIIIIIII", buf)
    return dict(slot=f[1], free=f[3], cyc=f[4], captured=f[5],
                pushed=f[6], deq_off=f[7])


def ringdump(rfd):
    buf = bytearray(RD_SIZE)
    fcntl.ioctl(rfd, IOC_RINGDUMP, buf, True)
    vals = struct.unpack("<%dI" % (RD_SIZE // 4), buf)
    return vals[:6]


def readback(rfd, n=4096):
    buf = bytearray(RB_SIZE)
    struct.pack_into("<I", buf, 0, min(n, 4096))
    fcntl.ioctl(rfd, IOC_READBACK, buf, True)
    status = struct.unpack_from("<I", buf, 4)[0]
    return status, bytes(buf[8:8 + min(n, 4096)])


def push(rfd, setup, data_len, dir_in=True, has_data=True, has_status=True):
    cdata = (ctypes.c_ubyte * max(64, data_len))()
    txn = struct.pack("<8sIBBBBQII", setup, data_len, 1 if has_data else 0,
                      1 if has_status else 0, 1 if dir_in else 0, 0,
                      ctypes.addressof(cdata), 0, 0)
    return fcntl.ioctl(rfd, IOC_PUSH, txn)


def warn_count():
    out = subprocess.run(["dmesg"], capture_output=True, text=True).stdout
    return len(re.findall(r"no TDs queued", out))


SHAPES = [
    ("A1-desc-device18",
     bytes([0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00]), 0x12, True),
    ("A2-desc-string3-B6",
     bytes([0x80, 0x06, 0x03, 0x03, 0x09, 0x04, 0xB6, 0x00]), 0xB6, True),
    ("A3-desc-string3-FF",
     bytes([0x80, 0x06, 0x03, 0x03, 0x09, 0x04, 0xFF, 0x00]), 0xFF, True),
    ("A4-dfu-getstatus",
     bytes([0xA1, 0x03, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00]), 0x06, True),
    ("B1-getstatus-40",
     bytes([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00]), 0x40, True),
    ("B2-getstatus-80",
     bytes([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00]), 0x80, True),
    ("B3-getstatus-0",
     bytes([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 0, True),
    ("B4-desc-string-EE",
     bytes([0x80, 0x06, 0xEE, 0x03, 0x09, 0x04, 0xFF, 0x00]), 0xFF, True),
    ("B5-desc-qualifier",
     bytes([0x80, 0x06, 0x00, 0x06, 0x00, 0x00, 0x0A, 0x00]), 0x0A, True),
    ("B7-desc-string-badlang",
     bytes([0x80, 0x06, 0x04, 0x03, 0x15, 0x04, 0xFF, 0x00]), 0xFF, True),
    ("B8-req-7f-40",
     bytes([0x80, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00]), 0x40, True),
    ("B9-dfu-getstate",
     bytes([0xA1, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]), 0x01, True),
    ("B10-dfu-clrstatus",
     bytes([0x21, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 0, False),
    ("B11-dfu-abort",
     bytes([0x21, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 0, False),
    ("B12-dfu-dnload0",
     bytes([0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 0, False),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shape", required=True,
                    help="shape index or name")
    args = ap.parse_args()
    if args.shape.isdigit():
        i = int(args.shape)
    else:
        names = [s[0] for s in SHAPES]
        if args.shape not in names:
            print("valid: %s" % ", ".join(
                "%d:%s" % (j, n) for j, n in enumerate(names)))
            return 1
        i = names.index(args.shape)
    name, setup, dlen, din = SHAPES[i]

    rfd = os.open("/dev/raw0", os.O_RDWR)
    st0 = state(rfd)
    h0 = ringdump(rfd)
    w0 = warn_count()
    print("[%s] captured=%d pushed=%d deq_off=%d enq=%d ctxdq=%d epst=%d warns=%d"
          % (name, st0["captured"], st0["pushed"], st0["deq_off"],
             h0[0], h0[2], h0[3], w0))
    if not st0["captured"]:
        print("NO CAPTURE")
        return 1

    # zero the staging witness: push a marker? No - we cannot clear staging
    # from userspace; instead record current content as baseline.
    _, base = readback(rfd, 64)
    print("staging before: %s" % base[:24].hex())

    push(rfd, setup, dlen, din,
         has_data=bool(dlen), has_status=True)
    print("pushed enq %d -> ?" % h0[0])

    # fetch kick: kernel URB doorbell
    ret, data, ms = serve()
    print("kick serve: ret=%r %dms cpid=%s"
          % (ret, ms, "CPID" in data.decode("utf-16le", "ignore")))

    time.sleep(0.3)
    st1 = state(rfd)
    h1 = ringdump(rfd)
    w1 = warn_count()
    print("after: pushed=%d deq_off=%d enq=%d ctxdq=%d epst=%d warns=%d(+%d)"
          % (st1["pushed"], st1["deq_off"], h1[0], h1[2], h1[3], w1, w1 - w0))

    out = b""
    if din and dlen:
        stat, rb = readback(rfd, 64)
        out = rb
        print("staging after: %s" % rb[:32].hex())
        if rb[:24] != base[:24]:
            print("STAGING CHANGED")
        if b"\xac\x05\x27\x12" in rb[:24]:
            print("SIG: device descriptor")
        if rb.startswith(b"\x03\x18"):
            print("SIG: descriptor-type string header")
        try:
            txt = rb.decode("utf-16le", "ignore")
            if "CPID" in txt:
                print("SIG: CPID string in staging")
        except Exception:
            pass

    # health probe: a second serve must still work
    ret2, _, ms2 = serve()
    print("health serve: ret=%r %dms" % (ret2, ms2))
    ok = (ret == 182 or ret == 255) and (ret2 == 182 or ret2 == 255)
    print("VERDICT %s: served=%s healthy=%s" % (name, out != base, ok))
    return 0


if __name__ == "__main__":
    sys.exit(main())
