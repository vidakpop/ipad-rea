#!/usr/bin/env python3
"""Decode the EP0 out-context dequeue pointer vs the software ring pointers.

Read-only diagnostics: RINGDUMP + STATE. The out_ctx block (1024B) holds:
  bytes 0-63   slot context (64-byte contexts on this AMD chip)
  bytes 64-127 EP0 context
EP ctx layout: DW0 ep_info @0, DW1 ep_info2 @4, TR dequeue ptr (64-bit) @8.
We decode the EP0 dq_ptr and where it falls relative to the sw view.
"""
import fcntl
import os
import struct
import sys

NDUMP = 48
RD_SIZE = 6 * 4 + NDUMP * 4 * 4 + 1024
ST_SIZE = 40
IOC_STATE = (2 << 30) | (ST_SIZE << 16) | (ord("R") << 8) | 3
IOC_RINGDUMP = (2 << 30) | (RD_SIZE << 16) | (ord("R") << 8) | 6

fd = os.open("/dev/raw0", os.O_RDWR)
st = bytearray(ST_SIZE)
fcntl.ioctl(fd, IOC_STATE, st, True)
f = struct.unpack("<QIIIIIIII", st)
print("state: slot=%d ring_lo=%#x free=%d cyc=%d captured=%d pushed=%d deq_off=%d"
      % (f[1], f[2], f[3], f[4], f[5], f[6], f[7]))

rd = bytearray(RD_SIZE)
fcntl.ioctl(fd, IOC_RINGDUMP, rd, True)
words = struct.unpack("<%dI" % (RD_SIZE // 4), rd)
enq, cyc, hwdeq, epst, slot, ntrb = words[:6]
print("ring: enq=%d cyc=%d hwdeq(probe)=%d epst=%d slot=%d ntrb=%d"
      % (enq, cyc, hwdeq, epst, slot, ntrb))

ctx = words[6 + NDUMP * 4:]
# u32 words of the 1024-byte out_ctx
slot_dw0 = ctx[0]
print("slot ctx DW0=%#010x (addr low byte=%#04x state=%#x)"
      % (slot_dw0, slot_dw0 & 0xff, (slot_dw0 >> 27) & 0x1f))

ep0_dw0 = ctx[16]     # bytes 64
ep0_dw1 = ctx[17]     # bytes 68 (ep_info2)
dq_lo = ctx[18]       # bytes 72
dq_hi = ctx[19]
dq = (dq_hi << 32) | dq_lo
print("EP0 ctx: dw0=%#010x dw1=%#010x dq_ptr=%#018x" % (ep0_dw0, ep0_dw1, dq))

# TRB words dump: find link TRBs (type 6) and any TRB with the dq pointer
for i in range(NDUMP):
    w0, w1, w2, w3 = words[6 + i * 4: 6 + i * 4 + 4]
    typ = (w3 >> 10) & 0x3f
    cycb = w3 & 1
    marker = ""
    if typ == 6:
        marker = "  <-- LINK (target seg base %010x TC=%d cyc=%d)" \
                 % (w0 | (w1 << 32), (w3 >> 1) & 1, cycb)
    if i % 8 == 0:
        print("--- trb idx %d ---" % i)
    if typ == 6 or (i >= enq - 4 and i <= enq + 2 and enq < NDUMP) or i == hwdeq:
        print("  %3d cyc=%d typ=%2d %08x %08x %08x %08x%s"
              % (i, cycb, typ, w0, w1, w2, w3, marker))
