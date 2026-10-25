#!/usr/bin/env python3
"""
recovery-cmd.py — send a command to an iPad in recovery mode (05ac:1281) and
print the response. Minimal ctypes/libusb client for the iBEC recovery command
channel (same protocol as libirecovery: send = ctrl OUT 0x40/0, recv = ctrl IN
0xC0/0).

Usage:
    python3 tools/recovery-cmd.py "printenv boot-args"
    python3 tools/recovery-cmd.py help
    python3 tools/recovery-cmd.py --serial        # just read the USB serial
"""

import ctypes
import sys
import time
from ctypes import (POINTER, Structure, byref, c_int, c_uint8, c_uint16,
                    c_uint32, c_void_p, create_string_buffer)

VENDOR_APPLE = 0x05AC
PRODUCT_RECOVERY = 0x1281


class DeviceDescriptor(Structure):
    _fields_ = [
        ('bLength', c_uint8), ('bDescriptorType', c_uint8), ('bcdUSB', c_uint16),
        ('bDeviceClass', c_uint8), ('bDeviceSubClass', c_uint8),
        ('bDeviceProtocol', c_uint8), ('bMaxPacketSize0', c_uint8),
        ('idVendor', c_uint16), ('idProduct', c_uint16), ('bcdDevice', c_uint16),
        ('iManufacturer', c_uint8), ('iProduct', c_uint8),
        ('iSerialNumber', c_uint8), ('bNumConfigurations', c_uint8),
    ]


def load_libusb():
    for name in ['libusb-1.0.so.0', 'libusb-1.0.so', 'libusb-1.0.so.0.4.0']:
        try:
            return ctypes.CDLL(name)
        except OSError:
            continue
    sys.exit('error: libusb-1.0 not found')


class Recovery:
    def __init__(self):
        self.lib = load_libusb()
        L = self.lib
        L.libusb_init.argtypes = [POINTER(c_void_p)]
        L.libusb_get_device_list.argtypes = [c_void_p, POINTER(POINTER(c_void_p))]
        L.libusb_get_device_list.restype = ctypes.c_ssize_t
        L.libusb_free_device_list.argtypes = [POINTER(c_void_p), c_int]
        L.libusb_get_device_descriptor.argtypes = [c_void_p, POINTER(DeviceDescriptor)]
        L.libusb_open.argtypes = [c_void_p, POINTER(c_void_p)]
        L.libusb_close.argtypes = [c_void_p]
        L.libusb_claim_interface.argtypes = [c_void_p, c_int]
        L.libusb_release_interface.argtypes = [c_void_p, c_int]
        L.libusb_kernel_driver_active.argtypes = [c_void_p, c_int]
        L.libusb_detach_kernel_driver.argtypes = [c_void_p, c_int]
        L.libusb_get_configuration.argtypes = [c_void_p, POINTER(c_int)]
        L.libusb_set_configuration.argtypes = [c_void_p, c_int]
        L.libusb_set_interface_alt_setting.argtypes = [c_void_p, c_int, c_int]
        L.libusb_control_transfer.argtypes = [c_void_p, c_uint8, c_uint8, c_uint16,
                                               c_uint16, c_void_p, c_uint16, c_uint32]
        L.libusb_control_transfer.restype = c_int
        L.libusb_bulk_transfer.argtypes = [c_void_p, c_uint8, c_void_p, c_int,
                                           POINTER(c_int), c_uint32]
        L.libusb_bulk_transfer.restype = c_int
        self.ctx = c_void_p()
        if L.libusb_init(byref(self.ctx)) != 0:
            sys.exit('error: libusb_init failed')

    def find(self, product, timeout=5.0):
        L = self.lib
        start = time.time()
        while True:
            devs = POINTER(c_void_p)()
            n = L.libusb_get_device_list(self.ctx, byref(devs))
            found = None
            for i in range(n):
                desc = DeviceDescriptor()
                if L.libusb_get_device_descriptor(devs[i], byref(desc)) == 0 \
                        and desc.idVendor == VENDOR_APPLE and desc.idProduct == product:
                    found = devs[i]
                    break
            L.libusb_free_device_list(devs, 1)
            if found is not None:
                handle = c_void_p()
                if L.libusb_open(found, byref(handle)) != 0:
                    sys.exit('error: libusb_open failed (permissions? udev rule needed)')
                # libirecovery setup: configuration 1; recovery mode (0x1281) also
                # claims interface 1 and selects altsetting 1 (the command channel).
                cur = c_int(0)
                L.libusb_get_configuration(handle, byref(cur))
                if cur.value != 1:
                    if L.libusb_set_configuration(handle, 1) != 0:
                        sys.exit('error: libusb_set_configuration(1) failed')
                for iface in (0, 1) if product == PRODUCT_RECOVERY else (0,):
                    if L.libusb_kernel_driver_active(handle, iface) == 1:
                        L.libusb_detach_kernel_driver(handle, iface)
                    rc = L.libusb_claim_interface(handle, iface)
                    if rc != 0:
                        sys.exit('error: libusb_claim_interface(%d) failed (%d)' % (iface, rc))
                if product == PRODUCT_RECOVERY:
                    rc = L.libusb_set_interface_alt_setting(handle, 1, 1)
                    if rc != 0:
                        sys.exit('error: set_interface_alt_setting(1,1) failed (%d)' % rc)
                return found, handle
            if time.time() - start > timeout:
                return None, None
            time.sleep(0.05)

    def ctrl(self, handle, bmRequestType, bRequest, wValue, wIndex, data, timeout, length=None):
        L = self.lib
        if length is None:
            length = len(data) if data is not None else 0
        if data is None and length > 0:
            buf = create_string_buffer(length)
        elif data is None:
            buf = None
        else:
            buf = create_string_buffer(bytes(data), max(len(data), 1))
            length = len(data)
        rc = L.libusb_control_transfer(handle, bmRequestType, bRequest, wValue,
                                       wIndex, buf, length, timeout)
        return rc, (buf.raw[:rc] if (rc > 0 and buf is not None) else b'')

    def serial(self, handle, desc_index):
        rc, raw = self.ctrl(handle, 0x80, 6, (3 << 8) | desc_index, 0x0409, None, 1000)
        buf = create_string_buffer(512)
        n = self.lib.libusb_control_transfer(handle, 0x80, 6, (3 << 8) | desc_index,
                                             0x0409, buf, 511, 1000)
        if n > 4 and buf.raw[1] == 3:
            return buf.raw[2:n].decode('utf-16-le', 'replace')
        return ''

    def bulk_read(self, handle, endpoint, length, timeout):
        L = self.lib
        buf = create_string_buffer(length)
        transferred = c_int(0)
        rc = L.libusb_bulk_transfer(handle, endpoint, buf, length, byref(transferred), timeout)
        return rc, buf.raw[:transferred.value] if transferred.value > 0 else b''

    def drain_console(self, handle, total_ms=300):
        """Read and return any pending console output from bulk EP 0x81."""
        out = b''
        deadline = time.time() + total_ms / 1000.0
        while time.time() < deadline:
            rc, data = self.bulk_read(handle, 0x81, 0x1000, 100)
            if rc == 0 and data:
                out += data
            elif rc != 0:
                break
        return out

    def command(self, handle, cmd):
        # xerub/irecovery protocol for iBEC recovery mode (05ac:1281):
        #   send command  = ctrl OUT 0x40/0, NUL-terminated
        #   console/resp  = bulk IN on EP 0x81 (interface 1, altsetting 1)
        # The device stalls new commands while unread output is queued on
        # EP 0x81, so drain it first.
        self.drain_console(handle)
        src, _ = self.ctrl(handle, 0x40, 0, 0, 0, cmd.encode() + b'\x00', 5000)
        time.sleep(0.15)
        out = self.drain_console(handle, 600)
        # some responses also come back on the control channel
        rc, raw = self.ctrl(handle, 0xC0, 0, 0, 0, None, 5000, length=2048)
        if raw:
            out += b'\n[ctrl 0xC0] ' + raw
        return (src, rc), out


def main():
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    rec = Recovery()
    dev, handle = rec.find(PRODUCT_RECOVERY)
    if handle is None:
        sys.exit('error: no device in recovery mode (05ac:1281)')
    try:
        if args[0] == '--serial':
            desc = DeviceDescriptor()
            rec.lib.libusb_get_device_descriptor(dev, byref(desc))
            print(rec.serial(handle, desc.iSerialNumber))
            return
        cmd = ' '.join(args)
        (src, rc), raw = rec.command(handle, cmd)
        print('send_rc=%d recv_rc=%d' % (src, rc))
        if raw:
            print('--- response (%d bytes) ---' % len(raw))
            print(raw.decode('utf-8', 'replace'))
            print('--- hex ---')
            print(raw.hex())
    finally:
        rec.lib.libusb_release_interface(handle, 0)
        rec.lib.libusb_close(handle)


if __name__ == '__main__':
    main()
