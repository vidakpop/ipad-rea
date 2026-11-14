#!/usr/bin/env python3
"""pwn-stageB.py — the bridge: open the DFU device, one port reset, exit.

Fresh libusb context (no prior transfers in this process — the crash class
from tonight's segfault cannot exist here). The module's ftrace hook
re-captures when the kernel re-addresses the device after this reset.
"""
import sys
import time

import importlib.util
import os

TOOLS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools')
spec = importlib.util.spec_from_file_location('pwn', os.path.join(TOOLS, 'checkm8-a5-pwn.py'))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


def main():
    usb = P.LibUSB()
    P.LibUSB._current = usb
    dev, handle, desc, serial = P.acquire(usb, want_serial=False)
    if not dev:
        print('[B] error: device not openable for the bridge')
        return 1
    print('[B] device:', usb.describe(dev))
    rc = usb.reset(handle)
    print('[B] port reset rc=%d' % rc)
    usb.lib.libusb_release_interface(handle, 0)
    usb.lib.libusb_close(handle)
    time.sleep(2.0)
    print('[B-OK] bridge done; module hook should hold the new capture')
    return 0


if __name__ == '__main__':
    sys.exit(main())
