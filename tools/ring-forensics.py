#!/usr/bin/env python3
"""Ring forensics for raw0: STATE + RINGDUMP, optional complete-TD PUSH.

Usage:
  sudo python3 tools/ring-forensics.py            # dump A (baseline)
  sudo python3 tools/ring-forensics.py --push     # dump A, push one complete
                                                  # control TD, dump B, diff

The RINGDUMP ioctl returns the EP0 ring's first 48 TRBs as raw u32 words.
Cycle bit = word3 bit0. xHC consumes a TRB only when its cycle bit matches
the ring's current DCS; a mismatch is silent (xHC treats the ring as empty).
"""
import fcntl
import ctypes
import struct
import sys

NDUMP = 48
RD_SIZE = 6 * 4 + NDUMP * 4 * 4  # 792
ST_SIZE = 40

IOC_PUSH = (1 << 30) | (32 << 16) | (ord("R") << 8) | 1
IOC_STATE = (2 << 30) | (ST_SIZE << 16) | (ord("R") << 8) | 3
IOC_RINGDUMP = (2 << 30) | (RD_SIZE << 16) | (ord("R") << 8) | 6

TRB_TYPES = {
    1: "RESERVED", 2: "LINK", 3: "TRANSFER", 4: "EVENT_DATA",
    5: "NO_OP",
    # command TRBs
    6: "ENABLE_SLOT", 7: "DISABLE_SLOT", 8: "ADDR_DEV", 9: "CONFIG_EP",
    10: "EVAL_CTX", 11: "RESET_EP", 12: "STOP_EP", 13: "SET_TR_DEQ",
    14: "RESET_DEV", 15: "FORCE_EVENT", 16: "NEG_BW", 17: "SET_LATENCY",
    18: "GET_PORT_BW", 19: "FORCE_HEADER", 20: "NO_OP_CMD",
}


def get_state(fd):
    # READ-direction opcode + immutable bytes arg → ioctl RETURNS the
    # payload; we use bytearray+mutate=False (proven ABI pattern on this
    # kernel: fcntl returns the buffer, unpack the return value).
    rc = fcntl.ioctl(fd, IOC_STATE, bytes(bytearray(ST_SIZE)), False)
    xb, slot, ring_lo, free, cyc, state, pushed, deq_off, ep0 = struct.unpack(
        "<QIIIIIIII", rc)
    return dict(xhci=xb, slot=slot, ring_lo=ring_lo, free=free, cyc=cyc,
                state=state, pushed=pushed, deq_off=deq_off, ep0=ep0)


def get_ringdump(fd):
    rc = fcntl.ioctl(fd, IOC_RINGDUMP, bytes(bytearray(RD_SIZE)), False)
    vals = struct.unpack("<%dI" % (RD_SIZE // 4), rc)
    head = dict(
        enq_idx=vals[0], cycle_state=vals[1], hw_deq_idx=vals[2],
        ep_state=vals[3], slot_id=vals[4], num_trbs=vals[5])
    trbs = []
    for i in range(NDUMP):
        w = vals[6 + i * 4: 6 + i * 4 + 4]
        trbs.append(dict(w0=w[0], w1=w[1], w2=w[2], w3=w[3],
                         cyc=w[3] & 1,
                         typ=(w[3] >> 10) & 0x3f,
                         chain=w[3] >> 4 & 1, ioc=(w[3] >> 5) & 1))
    return head, trbs


def fmt_head(tag, h):
    print("[%s] enq_idx=%-3d cycle_state=%d hw_deq=%-3s ep_state=%s slot=%d"
          % (tag, h["enq_idx"], h["cycle_state"],
             "none" if h["hw_deq_idx"] == 0xFFFFFFFF else str(h["hw_deq_idx"]),
             {1: "RUN", 2: "HALT", 3: "STOP"}.get(h["ep_state"],
                                                  h["ep_state"]),
             h["slot_id"]))


def fmt_trbs(tag, h, trbs):
    dcs = h["cycle_state"]
    print("  idx cyc dcs? type        w0          w1          w2          w3")
    for i, t in enumerate(trbs):
        mark = []
        if i == h["enq_idx"]:
            mark.append("ENQ")
        if h["hw_deq_idx"] != 0xFFFFFFFF and i == h["hw_deq_idx"]:
            mark.append("HWDEQ")
        typ = TRB_TYPES.get(t["typ"], "?%d" % t["typ"])
        line = ("  %3d  %d  %-3s  %-11s %08x    %08x    %08x    %08x %s"
                % (i, t["cyc"], "OK" if t["cyc"] == dcs else "BAD",
                   typ, t["w0"], t["w1"], t["w2"], t["w3"],
                   " ".join(mark)))
        print(line)


def push_complete_td(fd):
    """One complete control TD: GET_DESCRIPTOR(device) 18 bytes IN + status."""
    setup = bytes([0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00])
    cdata = (ctypes.c_ubyte * 18)()
    txn = struct.pack("<8sIBBBBQII",
                      setup, 18, 1, 1, 1, 0,
                      ctypes.addressof(cdata), 0, 0)
    assert len(txn) == 32, len(txn)
    rc = fcntl.ioctl(fd, IOC_PUSH, txn)
    return rc


def main():
    import os
    do_push = "--push" in sys.argv
    fd = os.open("/dev/raw0", os.O_RDWR)
    st = get_state(fd)
    print("[state] xhci=0x%x slot=%d ring=0x%x free=%d cyc=%d captured=%s "
          "pushed=%d deq_off=%d ep0(+32,ignore)=%d"
          % (st["xhci"], st["slot"], st["ring_lo"], st["free"], st["cyc"],
             "yes" if st["state"] else "NO", st["pushed"], st["deq_off"],
             st["ep0"]))
    if not st["state"]:
        print("no capture - aborting")
        sys.exit(1)
    hA, tA = get_ringdump(fd)
    fmt_head("A", hA)
    fmt_trbs("A", hA, tA)
    if do_push:
        print(">> pushing complete TD (GET_DESCRIPTOR device, 18B IN, status)")
        rc = push_complete_td(fd)
        print(">> push rc=%r" % (rc,))
        hB, tB = get_ringdump(fd)
        fmt_head("B", hB)
        fmt_trbs("B", hB, tB)
        print(">> diff:")
        ch = 0
        for i in range(NDUMP):
            a, b = tA[i], tB[i]
            if a["w0"] != b["w0"] or a["w1"] != b["w1"] or \
               a["w2"] != b["w2"] or a["w3"] != b["w3"]:
                print("   TRB %3d: %08x %08x %08x %08x  ->  %08x %08x %08x "
                      "%08x" % (i, a["w0"], a["w1"], a["w2"], a["w3"],
                                b["w0"], b["w1"], b["w2"], b["w3"]))
                ch += 1
        if ch == 0:
            print("   (no in-memory change)")


if __name__ == "__main__":
    main()
