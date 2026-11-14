#!/usr/bin/env python3
"""Legal DFU DNLOAD uploader: upload a .dfu image (iBSS/iBEC) into the
A5's DFU RAM image buffer via the DFU 1.1 protocol - nothing but
complete transactions.

Flow: chunked DFU_DNLOAD (0x21/1, 0x800 max per chunk) with a
DFU_GETSTATUS poll between chunks (the iBoot DFU handler's pacing),
zero-length DNLOAD as the end marker, then the GETSTATUS manifest
loop watching for the validation verdict and the USB transition
(05ac:1227 DFU -> 05ac:1281 recovery = the image booted).
"""
import ctypes
import fcntl
import glob
import importlib.util
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "dayone", os.path.join(HERE, "checkm8-a5-pwn.py"))
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)

CHUNK = 0x800


def dfu_present():
    for p in glob.glob("/sys/bus/usb/devices/*/idProduct"):
        try:
            if open(p).read().strip() == "1227":
                return True
        except OSError:
            pass
    return False


def recovery_present():
    for p in glob.glob("/sys/bus/usb/devices/*/idProduct"):
        try:
            if open(p).read().strip() == "1281":
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


def dnload(usb, handle, block, chunk):
    l = len(chunk)
    rc, info = usb.raw_ctrl(handle, 0x21, 1, block, 0, l, chunk,
                            abandon=False, timeout_ms=2000,
                            name='dn%d' % block)
    return info


def getstatus(usb, handle):
    rc, info = usb.raw_ctrl(handle, 0xA1, 3, 0, 0, 6, b'',
                            abandon=False, timeout_ms=2000,
                            name='getstatus')
    if info[0] == 0 and info[1] >= 6:
        return True
    return False


def main():
    path = sys.argv[1]
    img = open(path, 'rb').read()
    print("image: %s (%d bytes)" % (path, len(img)), flush=True)
    if not wait_dance():
        print("no entry", flush=True)
        return 1
    print("DFU in - settling", flush=True)
    time.sleep(1.5)
    usb = d.LibUSB()
    dev, handle, desc, _ = d.acquire(usb, want_serial=False)

    blocks = (len(img) + CHUNK - 1) // CHUNK
    print("uploading %d blocks of %#x" % (blocks, CHUNK), flush=True)
    t0 = time.time()
    for b in range(blocks):
        chunk = img[b * CHUNK:(b + 1) * CHUNK]
        info = dnload(usb, handle, b, chunk)
        if info[0] != 0:
            print("block %d: %s (%d) - ABORT"
                  % (b, d.STATUS_NAMES[info[0]], info[1]), flush=True)
            return 1
        ok = getstatus(usb, handle)
        if not ok:
            print("block %d: getstatus failed - ABORT" % b, flush=True)
            return 1
        if b % 8 == 0 or b == blocks - 1:
            print("  block %d/%d %dms"
                  % (b + 1, blocks, (time.time() - t0) * 1000), flush=True)
    print("data sent - end marker", flush=True)
    rc, info = usb.raw_ctrl(handle, 0x21, 1, 0, 0, 0, b'',
                            abandon=False, timeout_ms=2000, name='end')
    print("end marker: %s actual=%d" % (d.STATUS_NAMES[info[0]], info[1]),
          flush=True)

    # manifest/validation loop
    verdict = None
    for i in range(60):
        try:
            usb2 = d.LibUSB()
            dev2, handle2, _, _ = usb2.acquire(usb2, want_serial=False)
            rc, info = usb2.raw_ctrl(handle2, 0xA1, 3, 0, 0, 6, b'',
                                     abandon=False, timeout_ms=1500,
                                     name='poll%d' % i)
            s, a = info[0], info[1]
            print("poll %d: %s actual=%d" % (i, d.STATUS_NAMES[s], a),
                  flush=True)
            if s == 0 and a >= 6:
                verdict = "OK"
        except SystemExit as e:
            print("poll %d: device left DFU (%s)" % (i, e), flush=True)
            break
        except Exception as e:
            print("poll %d: %r" % (i, e), flush=True)
            break
        time.sleep(0.4)
        if recovery_present():
            print("*** RECOVERY MODE DEVICE PRESENT - IMAGE BOOTED ***",
                  flush=True)
            verdict = "BOOTED"
            break

    for j in range(8):
        if recovery_present():
            break
        time.sleep(1.0)
    final = "RECOVERY PRESENT" if recovery_present() else \
            ("DFU still" if dfu_present() else "gone")
    print("FINAL: %s (verdict=%s)" % (final, verdict), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
