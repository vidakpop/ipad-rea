#!/usr/bin/env python3
"""Window duo: research shape + A1 control stacked in one window.

Per window budget (ROM answers 1-4 transactions): push shape ->
kick(150ms) -> readback (shape's landing) -> push A1 control -> kick ->
readback (A1's 18-byte descriptor = window still alive). Two pieces
of evidence per window even when the kick between them dies.
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

RB_SIZE = 8 + 4096
ST_SIZE = 40
IOC_PUSH = (1 << 30) | (32 << 16) | (ord("R") << 8) | 1
IOC_STATE = (2 << 30) | (ST_SIZE << 16) | (ord("R") << 8) | 3
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


def serve(timeout_ms=150, wlength=255):
    bus, dev = find_dev()
    if not bus:
        return None, b""
    fd = os.open("/dev/bus/usb/%03d/%03d" % (bus, dev), os.O_RDWR)
    buf = ctypes.create_string_buffer(255)
    ct = CtrlTransfer(0x80, 6, 0x0303, 0x0409, wlength, timeout_ms,
                      ctypes.cast(buf, ctypes.c_void_p))
    try:
        n = fcntl.ioctl(fd, USBDEVFS_CONTROL, ct)
        return n, buf.raw[:max(0, n)]
    except OSError as e:
        return -e.errno, b""
    finally:
        os.close(fd)


def state(rfd):
    buf = bytearray(ST_SIZE)
    fcntl.ioctl(rfd, IOC_STATE, buf, True)
    f = struct.unpack("<QIIIIIIII", buf)
    return dict(slot=f[1], free=f[3], cyc=f[4], captured=f[5],
                pushed=f[6], deq_off=f[7])


def readback(rfd, n=64):
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


SHAPES = {
    "B1": ("getstatus-40",
           bytes([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00]), 0x40, True),
    "B2": ("getstatus-80",
           bytes([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00]), 0x80, True),
    "B3": ("getstatus-0",
           bytes([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 0, True),
    "B4": ("desc-string-EE",
           bytes([0x80, 0x06, 0xEE, 0x03, 0x09, 0x04, 0xFF, 0x00]), 0xFF, True),
    "B5": ("desc-qualifier",
           bytes([0x80, 0x06, 0x00, 0x06, 0x00, 0x00, 0x0A, 0x00]), 0x0A, True),
    "B7": ("desc-string-badlang",
           bytes([0x80, 0x06, 0x04, 0x03, 0x15, 0x04, 0xFF, 0x00]), 0xFF, True),
    "B8": ("req-7f-40",
           bytes([0x80, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00]), 0x40, True),
    "A4": ("dfu-getstatus",
           bytes([0xA1, 0x03, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00]), 0x06, True),
    "B9": ("dfu-getstate",
           bytes([0xA1, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]), 0x01, True),
    "B10": ("dfu-clrstatus",
            bytes([0x21, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 0, False),
    "B11": ("dfu-abort",
            bytes([0x21, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 0, False),
    "B12": ("dfu-dnload0",
            bytes([0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 0, False),
}
A1 = (bytes([0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00]), 0x12, True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shape", required=True)
    args = ap.parse_args()
    if args.shape not in SHAPES:
        print("valid: %s" % ",".join(SHAPES))
        return 1
    name, setup, dlen, din = SHAPES[args.shape]

    rfd = os.open("/dev/raw0", os.O_RDWR)
    st = state(rfd)
    if not st["captured"]:
        print("NO CAPTURE")
        return 1
    w0 = warn_count()
    print("duo %s: pushed=%d deq_off=%d" % (args.shape, st["pushed"], st["deq_off"]))

    # research shape
    push(rfd, setup, dlen, din, has_data=bool(dlen))
    ret1, _ = serve()
    time.sleep(0.12)
    w1 = warn_count()
    _, rb1 = readback(rfd, 64)
    nz1 = sum(1 for b in rb1 if b)
    print("shape: kick=%-5r exec=%-5s staging-nz=%-3d %s"
          % (ret1, w1 > w0, nz1, rb1[:40].hex()))

    # A1 control: proves the window survived past the research shape
    push(rfd, A1[0], A1[1], A1[2], has_data=True)
    ret2, _ = serve()
    time.sleep(0.12)
    w2 = warn_count()
    _, rb2 = readback(rfd, 24)
    a1ok = rb2.startswith(b"\x12\x01\x00\x02\x00\x00\x00\x40")
    print("ctrl : kick=%-5r exec=%-5s a1-landed=%-5s %s"
          % (ret2, w2 > w1, a1ok, rb2[:18].hex()))

    # signatures on the research staging
    sig = ""
    if dlen and din:
        if nz1 > 0:
            sig = "NONZERO-DATA"
        else:
            sig = "zero"
    print("VERDICT %s: shape-exec=%s shape-data-nz=%d ctrl-alive=%s kicks=%r/%r"
          % (args.shape, w1 > w0, nz1, a1ok or w2 > w1, ret1, ret2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
