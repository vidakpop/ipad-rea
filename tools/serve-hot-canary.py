#!/usr/bin/env python3
"""Serve-hot canary: usbfs serve (NO reset) immediately followed by a
pushed complete TD, then staging readback.

Proves whether a plain kernel URB serve (device active hot on the wire)
is sufficient to make the very next module push execute - i.e. whether
the 'fresh-hot chip' condition is what makes pushes run, without the
42-second port-reset storm.
"""
import ctypes
import fcntl
import glob
import os
import struct
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


def usbfs_serve_string3():
    bus, dev = find_dev()
    if not bus:
        return None
    fd = os.open("/dev/bus/usb/%03d/%03d" % (bus, dev), os.O_RDWR)
    buf = ctypes.create_string_buffer(255)
    ct = CtrlTransfer(0x80, 6, 0x0303, 0x0409, 255, 2000,
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
    return vals[:6], vals


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


def main():
    rfd = os.open("/dev/raw0", os.O_RDWR)
    st = state(rfd)
    print("state0: captured=%d pushed=%d deq_off=%d" %
          (st["captured"], st["pushed"], st["deq_off"]))
    if not st["captured"]:
        print("NO CAPTURE")
        return 1

    # 1) plain kernel serve - no reset, just a control URB
    t0 = time.time()
    n, data = usbfs_serve_string3()
    print("serve: ret=%r len=%d in %.0fms cpid=%s"
          % (n, len(data), (time.time() - t0) * 1000,
             "CPID" in data.decode("utf-16le", "ignore")))

    # 2) immediate canary push (t+~0ms)
    setup = bytes([0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00])
    push(rfd, setup, 0x12)

    # 3) evidence
    time.sleep(0.35)
    stat, rb = readback(rfd, 64)
    print("readback: %s" % rb[:24].hex())
    sig = b"\x12\x01\x00\x02\x00\x00\x00\x40\xac\x05\x27\x12"
    print("descriptor served: %s" % ("YES" if rb.startswith(sig) else "NO"))
    st1 = state(rfd)
    print("state1: pushed=%d deq_off=%d" % (st1["pushed"], st1["deq_off"]))
    return 0 if rb.startswith(sig) else 2


if __name__ == "__main__":
    sys.exit(main())
