#!/usr/bin/env python3
"""Analyze the k93 iBEC (iPad2,1, iOS 9.3.5 13G36, iBoot-2817) to re-derive
the five constants Cascadia's scripts/firmware/patch-ibec-autogo.py hardcodes
for the p105 iBEC (iBoot-2261, 8.4.1):

  HOOK_OFF        4-byte hook site inside the USB bulk RX completion callback
                  (stock bytes: ldr r0,[pc,#x] ; movs r1,#1)
  TRAMPOLINE_OFF  free code cave (>= ~96 bytes of 0x00/0xFF)
  CACHE_FLUSH     VA of iBoot's cache-flush routine
  DONE_FLAG       VA of the transfer-done flag byte the callback sets
  USB_CONTINUE    VA the caller continues at after the callback returns

Usage: analyze-ibec-k93.py <iBEC.patched> [--disasm OFF]
Needs capstone:  LIBCAPSTONE_PATH=/path/to/capstone-build \
                PYTHONPATH=/path/to/capstone/bindings/python
"""
from __future__ import annotations

import argparse
import re
import struct
import sys

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs


def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def find_bl_targets(data: bytes, base: int) -> dict[int, list[int]]:
    """Scan for Thumb-32 BL instructions; return {target_va: [caller_off, ...]}."""
    xrefs: dict[int, list[int]] = {}
    i = 0
    while i < len(data) - 4:
        h1 = struct.unpack_from("<H", data, i)[0]
        h2 = struct.unpack_from("<H", data, i + 2)[0]
        if (h1 & 0xF800) == 0xF000 and (h2 & 0xD000) == 0xD000:
            s = (h1 >> 10) & 1
            imm10 = h1 & 0x3FF
            j1 = (h2 >> 13) & 1
            j2 = (h2 >> 11) & 1
            imm11 = h2 & 0x7FF
            i1 = 1 ^ (j1 ^ s)
            i2 = 1 ^ (j2 ^ s)
            off32 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
            if s:
                off32 |= 0xFE000000
            target = ((base + i + 4 + off32) & 0xFFFFFFFF)
            xrefs.setdefault(target, []).append(i)
        i += 2
    return xrefs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("ibec")
    ap.add_argument("--disasm", help="disassemble 0x100 bytes at file offset (hex)")
    args = ap.parse_args()

    data = open(args.ibec, "rb").read()
    base = u32(data, 0x20) & ~0xFFFFF
    print(f"file {args.ibec}: {len(data):#x} bytes, image base {base:#010x}")

    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

    if args.disasm:
        off = int(args.disasm, 16)
        for insn in cs.disasm(data[off:off + 0x100], base + off):
            print(f"  {insn.address:#010x}  {insn.bytes.hex():<10} {insn.mnemonic:<8} {insn.op_str}")
        return 0

    # ---- A. hook-site candidates -------------------------------------------
    # Unconditional `ldr r0,[pc,#x]` (0x48xx) ; `movs r1,#1` (0x2101), not in
    # an IT block, with `strb r1,[r0]` (0x7001) soon after and a pop {...,lr}
    # tail.  This is the stock "mark transfer done" sequence at the end of the
    # USB bulk RX completion callback.
    print("\n=== A. hook-site candidates (ldr r0,[pc,#x]; movs r1,#1; ... strb; ... pop) ===")
    pat = re.compile(rb".\x48\x01\x21", re.S)
    for m in pat.finditer(data):
        off = m.start()
        if off % 2:
            continue
        prev = struct.unpack_from("<H", data, off - 2)[0] if off >= 2 else 0
        if (prev & 0xFF08) == 0xBF08:  # inside an IT block
            continue
        imm8 = data[off]
        ldr_pc = (base + off + 4) & ~3
        pool_off = (ldr_pc - base) + imm8 * 4
        if pool_off + 4 > len(data):
            continue
        flag_va = u32(data, pool_off)
        # the loaded value must be a data-region address (top of the image)
        if not (base + 0x30000 <= flag_va < base + len(data)):
            continue
        # look ahead: strb r1,[r0] (0x7001) then a pop including lr within 0x30
        window = data[off + 4: off + 4 + 0x30]
        insns = list(cs.disasm(window, base + off + 4))
        strb_at = next((i for i, x in enumerate(insns)
                        if x.mnemonic == "strb" and x.op_str == "r1, [r0]"), None)
        if strb_at is None:
            continue
        pop_at = next((i for i, x in enumerate(insns)
                       if x.mnemonic.startswith("pop") and "lr" in x.op_str
                       and "r4" in x.op_str and "r5" in x.op_str), None)
        if pop_at is None:
            continue
        # look behind: push {r4,r5,r7,lr} prologue within 0x120 bytes
        back = list(cs.disasm(data[max(0, off - 0x120):off], base + max(0, off - 0x120)))
        push_ok = any(x.mnemonic.startswith("push") and "r4" in x.op_str
                      and "r5" in x.op_str and "lr" in x.op_str for x in back)
        # byte-count load ldr rX,[r4,#0x10] (0x6920-0x6927) anywhere nearby
        near = data[max(0, off - 0x120): off + 0x40]
        cnt_hit = bool(re.search(rb"[\x20-\x27]\x69", near))
        print(f"  hook @ file {off:#x} va {base + off:#x}  flag_va {flag_va:#010x}  "
              f"push_prologue={push_ok}  ldr_[r4,#0x10]_nearby={cnt_hit}")
        for insn in insns[:pop_at + 1]:
            print(f"      {insn.address:#010x}  {insn.mnemonic:<8} {insn.op_str}")

    # ---- B. functions referencing the transfer byte count [r4,#0x10] -------
    print("\n=== B. ldr rX,[r4,#0x10] (transfer byte count) hits ===")
    for m in re.finditer(rb"[\x20-\x27]\x69", data):
        off = m.start()
        if off % 2:
            continue
        rt = data[off] & 7
        print(f"  file {off:#x} va {base + off:#x}  ldr r{rt}, [r4, #0x10]")

    # ---- C. caves -----------------------------------------------------------
    print("\n=== C. free caves >= 96 bytes (0x00 or 0xff) ===")
    i = 0
    while i < len(data) - 96:
        b = data[i]
        if b in (0x00, 0xFF):
            j = i
            while j < len(data) and data[j] == b:
                j += 1
            if j - i >= 96:
                print(f"  file {i:#x} va {base + i:#x}  len={j - i}  fill={b:#04x}")
            i = j
        else:
            i += 1

    # ---- D. cache-flush candidates (functions with several mcr p15) --------
    print("\n=== D. cache-flush candidates (>=3 mcr p15 in <=0x80 bytes) ===")
    i = 0
    while i < len(data) - 4:
        # crude function-ish window scan: disassemble forward, stop at pop/bx lr
        insns = []
        for insn in cs.disasm(data[i:i + 0x80], base + i):
            insns.append(insn)
            if insn.mnemonic in ("bx",) and insn.op_str == "lr":
                break
            if insn.mnemonic.startswith("pop") and "pc" in insn.op_str:
                break
        mcrs = [x for x in insns if x.mnemonic == "mcr" and "p15" in x.op_str]
        if len(mcrs) >= 3 and 0x10 <= len(insns) <= 0x30:
            print(f"  fn @ file {i:#x} va {base + i:#x}  insns={len(insns)}  mcr_p15={len(mcrs)}")
            for insn in insns:
                print(f"      {insn.address:#010x}  {insn.mnemonic:<8} {insn.op_str}")
        i += 2

    # ---- E. strings of interest ---------------------------------------------
    print("\n=== E. strings ===")
    for s in [b"filesize variable invalid", b"get environment variable over usb",
              b"jump directly to address", b"\x00go\x00", b"memboot",
              b"Entering recovery mode"]:
        off = data.find(s)
        print(f"  {s!r}: {'file %#x va %#x' % (off, base + off) if off >= 0 else 'not found'}")

    # ---- F. 'go' command table -> jump helper -------------------------------
    print("\n=== F. command-table xrefs to the 'go' string ===")
    xrefs = find_bl_targets(data, base)
    for m in re.finditer(rb"\x00go\x00", data):
        soff = m.start() + 1  # the 'g'
        sva = base + soff
        ptr = struct.pack("<I", sva)
        for j in range(0, len(data) - 4):
            if data[j:j + 4] == ptr:
                entry = j & ~3
                handler = u32(data, entry + 4)
                helpva = u32(data, entry + 8)
                print(f"  'go' string file {soff:#x}; table entry file {entry:#x} "
                      f"handler va {handler:#010x} help va {helpva:#010x}")
                callers = xrefs.get(handler, [])
                print(f"    BL callers: {[hex(base + c) for c in callers[:8]]}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
