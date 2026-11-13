#!/usr/bin/env python3
"""Full pool forensic dump: find what the xDC writes into OUR 512K pool.

After bringup + doorbell + wait, scans the whole pool for non-zero content and
prints every non-zero run with offsets and values, plus targeted searches for
the chip's internal command pointer (0x1fa0 region) and the qword 0xffc81fa0.

Usage: sudo python3 tools/xdc-3-dump.py <dma-base-hex>
"""
import struct
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from xdc import Xdc  # noqa: E402


def main():
    if len(sys.argv) < 2:
        print("usage: xdc-3-dump.py <dma-base-hex>")
        return 1
    x = Xdc(dma=int(sys.argv[1], 16))
    print("OP=%d slots=%d ports=%d scratch=%d" %
          (x.OP, x.maxslots, x.maxports, x.scratch))
    x.arm_irq()
    x.bringup()
    print("[1] bringup ok; doorbell kick, wait 2s")
    x.events_clear()
    x.doorbell(0)
    x.wait_event(timeout=2.0)

    print("[2] full pool scan for chip-written content")
    POOL = 0x80000
    run_start = None
    runs = []
    off = 0
    while off < POOL:
        chunk = x.memck(off, 4096)
        for i in range(0, 4096, 16):
            addr = off + i
            blk = chunk[i:i + 16]
            nz = any(blk)
            if nz and run_start is None:
                run_start = addr
            if not nz and run_start is not None:
                runs.append((run_start, addr - run_start))
                run_start = None
        off += 4096
    if run_start is not None:
        runs.append((run_start, POOL - run_start))
    print("    %d non-zero runs" % len(runs))
    for rs, ln in runs:
        print("      +%#08x len %#x" % (rs, ln))

    print("[3] qword search for chip pointer values")
    search_terms = {
        "0xffc81fa0": struct.pack("<Q", 0xffc81fa0),
        "0xffc82000": struct.pack("<Q", 0xffc82000),
        "0xffcc2000": struct.pack("<Q", 0xffcc2000),
        "0xffc81fa0(lo32)": struct.pack("<I", 0xffc81fa0),
    }
    for label, pat in search_terms.items():
        off = 0
        hits = []
        while off < POOL:
            data = x.memck(off, 4096)
            base = off
            for i in range(0, 4096 - len(pat)):
                if data[i:i + len(pat)] == pat:
                    hits.append(base + i)
            off += 4096
        print("    %-16s hits: %s" % (label, [hex(h) for h in hits[:8]]))

    print("[4] hexdump pool+0x1f00..0x2000 (the phantom fetch zone)")
    data = x.memck(0x1f00, 0x100)
    for i in range(0, len(data), 16):
        print("      +%#06x  %s" % (0x1f00 + i, data[i:i + 16].hex()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
