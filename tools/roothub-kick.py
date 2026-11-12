#!/usr/bin/env python3
"""Force an xHCI port reset on a root hub port via libusb roothub control.

The kernel hub driver executes roothub requests against the hardware
directly (xhci_bus_resume/xhci_hub_control), so SET_FEATURE(PORT_RESET)
re-kicks the port hardware even after khubd gave up ("unable to
enumerate").  Usage: roothub-kick.py <bus> <port> [<retries>]
"""
import sys, time, ctypes
from ctypes import c_void_p, POINTER, byref, create_string_buffer, c_int

def main():
    bus, port = int(sys.argv[1]), int(sys.argv[2])
    retries = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    L = ctypes.CDLL('libusb-1.0.so.0', use_errno=True)
    L.libusb_init(c_void_p())  # default context
    L.libusb_get_device_list.argtypes = [c_void_p, POINTER(POINTER(c_void_p))]
    L.libusb_get_device_list.restype = ctypes.c_ssize_t
    devs = POINTER(c_void_p)()
    n = L.libusb_get_device_list(None, byref(devs))
    target = None
    for i in range(n):
        d = devs[i]
        L.libusb_get_bus_number.restype = c_int
        L.libusb_get_bus_number.argtypes = [c_void_p]
        if L.libusb_get_bus_number(d) == bus:
            L.libusb_get_device_address.restype = c_int
            L.libusb_get_device_address.argtypes = [c_void_p]
            if L.libusb_get_device_address(d) == 1:   # roothub
                target = d
                break
    if target is None:
        print('roothub for bus %d not found' % bus)
        return 1
    L.libusb_open.restype = c_int
    L.libusb_open.argtypes = [c_void_p, POINTER(c_void_p)]
    h = c_void_p()
    if L.libusb_open(target, byref(h)) != 0:
        print('failed to open roothub')
        return 1
    L.libusb_control_transfer.restype = c_int
    L.libusb_control_transfer.argtypes = [c_void_p, c_int, c_int, c_int, c_int,
                                          c_void_p, c_int, c_int]
    for r in range(retries):
        rc = L.libusb_control_transfer(h, 0x23, 0x03, 0x0004, port,
                                       None, 0, 1000)   # SET_FEATURE PORT_RESET
        print('SET_FEATURE(PORT_RESET) port %d -> rc=%d' % (port, rc))
        time.sleep(2.0)
    return 0

if __name__ == '__main__':
    sys.exit(main())
