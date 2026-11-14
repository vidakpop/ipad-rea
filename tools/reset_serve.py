#!/usr/bin/env python3
"""Guarded USBDEVFS_RESET + serve check.

Safe baseline restorer: issues the port reset (237ms-class on a healthy
device) so the fresh enumeration runs under the module's SET_CONFIGURATION
guard, then verifies the ROM serves a real CPID string read.
NEVER run this on a dirtied ring (see ledger crash report).
"""
import os
import fcntl
import ctypes
import glob
import time
import sys


def find():
    for p in glob.glob('/sys/bus/usb/devices/*/idProduct'):
        if open(p).read().strip() == '1227':
            node = os.path.dirname(p)
            return int(open(node + '/busnum').read()), int(
                open(node + '/devnum').read())
    return None, None


class CtrlTransfer(ctypes.Structure):
    _fields_ = [('bRequestType', ctypes.c_ubyte), ('bRequest', ctypes.c_ubyte),
                ('wValue', ctypes.c_ushort), ('wIndex', ctypes.c_ushort),
                ('wLength', ctypes.c_ushort), ('timeout', ctypes.c_uint),
                ('data', ctypes.c_void_p)]


USBDEVFS_CONTROL = (3 << 30) | (24 << 16) | (0x55 << 8) | 0   # _IOWR('U',0,24)
USBDEVFS_RESET = 0x5514                                      # _IO('U',20)


def main():
    busnum, devnum = find()
    if not busnum:
        print('NO DEVICE AT START')
        return 1
    fd = os.open('/dev/bus/usb/%03d/%03d' % (busnum, devnum), os.O_RDWR)
    t0 = time.time()
    try:
        fcntl.ioctl(fd, USBDEVFS_RESET)
        print('RESET ok in %.0fms' % ((time.time() - t0) * 1000))
    except OSError as e:
        print('RESET errno=%d after %.0fms' % (e.errno,
                                               (time.time() - t0) * 1000))
    os.close(fd)
    time.sleep(2.5)
    busnum, devnum = find()
    print('after: %s' % ('%03d/%03d' % (busnum, devnum) if busnum else 'GONE'))
    if not busnum:
        return 1
    fd = os.open('/dev/bus/usb/%03d/%03d' % (busnum, devnum), os.O_RDWR)
    for i in range(3):
        buf = ctypes.create_string_buffer(255)
        ct = CtrlTransfer(0x80, 6, 0x0303, 0x0409, 255, 2000,
                           ctypes.cast(buf, ctypes.c_void_p))
        try:
            n = fcntl.ioctl(fd, USBDEVFS_CONTROL, ct)
            txt = buf.raw.decode('utf-16le', 'ignore')
            print('serve%d: ret=%r %s' % (i, n,
                  txt[:44] if 'CPID' in txt else buf.raw[:8].hex()))
            if 'CPID' in txt:
                print('SERVES - GUARDED BASELINE HEALTHY')
                break
        except OSError as e:
            print('serve%d: errno=%d' % (i, e.errno))
        time.sleep(0.3)
    os.close(fd)
    return 0


if __name__ == '__main__':
    sys.exit(main())
