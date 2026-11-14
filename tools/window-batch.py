#!/usr/bin/env python3
"""Window batch: run several shape experiments inside one ROM window.

The ROM answers EP0 for a short period after each port reset storm;
then it goes deaf until the next reset. The xHC's fetch engine only
starts our pushed TDs when a kernel URB doorbell rings (the module's
own writel does not kick it). So the working cadence per shape:

  push the shape -> 150ms-timeout kick serve (kernel bell) ->
  readback staging -> next shape.

~0.5s per shape: a window fits 5-10 shapes. The caller storms between
windows via tools/reset_serve.py when this script reports DEAF.

Verdict fields per shape:
  exec   : warn-count increased (a module TD evented)
  data   : staging changed in a way that is not just our zero wipe
  kick   : the kick serve returned 182/255 (window still open)
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


SHAPES = {
    "A1": ("desc-device18",
           bytes([0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00]), 0x12, True),
    "A2": ("desc-string3",
           bytes([0x80, 0x06, 0x03, 0x03, 0x09, 0x04, 0xB6, 0x00]), 0xB6, True),
    "A3": ("desc-string3-FF",
           bytes([0x80, 0x06, 0x03, 0x03, 0x09, 0x04, 0xFF, 0x00]), 0xFF, True),
    "A4": ("dfu-getstatus",
           bytes([0xA1, 0x03, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00]), 0x06, True),
    "B1": ("getstatus-40",
           bytes([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00]), 0x40, True),
    "B2": ("getstatus-80",
           bytes([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00]), 0x80, True),
    "B4": ("desc-string-EE",
           bytes([0x80, 0x06, 0xEE, 0x03, 0x09, 0x04, 0xFF, 0x00]), 0xFF, True),
    "B5": ("desc-qualifier",
           bytes([0x80, 0x06, 0x00, 0x06, 0x00, 0x00, 0x0A, 0x00]), 0x0A, True),
    "B9": ("dfu-getstate",
           bytes([0xA1, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]), 0x01, True),
    "B10": ("dfu-clrstatus",
            bytes([0x21, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 0, False),
    "B11": ("dfu-abort",
            bytes([0x21, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 0, False),
    "B12": ("dfu-dnload0",
            bytes([0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 0, False),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shapes", required=True,
                    help="comma list, e.g. A1,A2,B1")
    args = ap.parse_args()
    keys = [k.strip() for k in args.shapes.split(",") if k.strip()]

    rfd = os.open("/dev/raw0", os.O_RDWR)
    st = state(rfd)
    if not st["captured"]:
        print("NO CAPTURE - re-arm first")
        return 1
    print("window-batch start: pushed=%d deq_off=%d" %
          (st["pushed"], st["deq_off"]))

    deaf = False
    for k in keys:
        if k not in SHAPES:
            print("%s: unknown shape" % k)
            continue
        name, setup, dlen, din = SHAPES[k]
        w0 = warn_count()
        _, base = readback(rfd, 32)

        push(rfd, setup, dlen, din, has_data=bool(dlen), has_status=True)
        ret, kickdata = serve()
        time.sleep(0.15)
        w1 = warn_count()
        st1 = state(rfd)
        _, rb = readback(rfd, 32)
        nonzero = any(rb)
        changed = rb != base
        sig = ""
        if b"\xac\x05\x27\x12" in rb[:24]:
            sig = " device-desc"
        elif rb[:2] == b"\x03\x18":
            sig = " string-desc"
        elif nonzero and din and dlen and len(rb) >= dlen:
            sig = " %dB-nonzero" % dlen
        print("%-6s kick=%-5r exec=%s data=%-5s deq_off=%-3d %s%s"
              % (k, ret, w1 > w0, changed, st1["deq_off"],
                 rb[:20].hex(), sig))
        if ret not in (182, 255):
            deaf = True
            print("DEAF after %s - storm needed" % k)
            break
    print("batch done deaf=%s" % deaf)
    return 0


if __name__ == "__main__":
    sys.exit(main())
