#!/usr/bin/env python3
"""
Patch k93 (iPad2,1) iBEC so it jumps to the Recovery bulk payload once the
upload's *final* USB chunk lands — the k93 analog of Project-Cascadia's
patch-ibec-autogo.py (p105).

Target: iBEC iBoot-2817, 13G36, image base 0x9ff00000 (iPad 2 / A5 / k93ap).

How it works
------------
iBEC's DFU/Recovery file-receive path arms one ep4 OUT bulk transfer on the
payload buffer at 0x80000000 (maxlen 0x4000000) with completion callback
0x9ff1fc31 (Thumb fn at 0x9ff1fc30).  irecovery -f sends the staging bundle in
0x8000-byte chunks, so the callback fires once per 0x8000 chunk; only the final
(short or zero-length) chunk reports [transfer+0x10] < 0x8000.

The stock data path of that callback ends (file 0x1fc8c) with:

    movs r0, #1          ; 01 20
    strb r0, [r5]        ; 28 70      <- ctx->done = 1   (r5 = ctx = 0x9ff4b750)
    add.w r0, r5, #0xc   ; r0 = ctx+0xc
    pop.w {r4, r5, r7, lr}
    b.w 0x9ff1c760       ; USB_CONTINUE(ctx+0xc)  -> re-arm next transfer

We replace the 4 bytes `01 20 28 70` with `b.w <trampoline>`.  The trampoline
(reached only on the count!=4 file-data path) tests the completion byte count:

  * count >= 0x8000  -> full chunk: replicate the stock tail (set done flag,
                       USB_CONTINUE) and keep receiving.
  * count <  0x8000  -> EOF: flush all caches (so the DMA'd/CPU-written payload
                       at 0x80000000 is coherent for execution), then `blx` to
                       the payload entry stored at ctx+8 (= 0x80000000).  The
                       entry is ARM state (bit0 clear), matching the
                       pongo-style linux_boot loader.  If the payload returns,
                       execution falls through to the stock continue path, so
                       USB stays alive.

Constants were found by RE (see tools/analyze-ibec-k93.py and
docs/k93-ibec-autogo.md):
  CACHE_FLUSH  0x9ff1d358  ARM no-arg "flush all caches": clean D-cache by
                           set/way (0x9ff1d23c) + invalidate I-cache
                           ICIALLU/DSB/ISB (0x9ff1d344).
  cave         file 0x1a4..0x200 (VA 0x9ff001a4): 92 bytes of unreferenced
                           zero padding between the boot halt-loop (0x9ff001a0
                           `b .`) and .rodata (version strings at 0x9ff00200).
                           Loaded, not .bss (bss clear covers 0x9ff47e80+),
                           never executed, 0 pointer references.

NOTE: keep the uploaded bundle size NOT a multiple of 0x8000 (pad it) so the
final completion is always a short chunk and the EOF test fires.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs

IBOOT_BASE = 0x9FF00000
HOOK_OFF = 0x1FC8C
HOOK_LEN = 4
HOOK_ORIG = bytes.fromhex("01202870")  # movs r0,#1 ; strb r0,[r5]
TRAMPOLINE_OFF = 0x1A4
TRAMPOLINE_MAX = 88  # cave is 0x1a4..0x200 (92 bytes); leave margin
CACHE_FLUSH = 0x9FF1D358  # ARM-mode, no args, flushes D+I caches
USB_CONTINUE = 0x9FF1C760
PKT = 0x8000
PAYLOAD_ENTRY_OFF = 8  # ctx+8 holds payload entry (0x80000000)


def iboot_base(data: bytes) -> int:
    import struct

    return struct.unpack_from("<I", data, 0x20)[0] & ~0xFFFFF


def _link_bytes(ld: str, asm: str, sym: str, want_va: int) -> bytes:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "patch.S").write_text(asm, encoding="ascii")
        (root / "patch.ld").write_text(ld, encoding="ascii")
        elf = root / "patch.elf"
        # --build-id=none is required: otherwise the linker emits a 0x24-byte
        # .note.gnu.build-id before .text and shifts the entry symbol off its
        # intended address, corrupting the PC-relative branch encodings.
        subprocess.run(
            [
                "arm-linux-gnueabihf-gcc",
                "-nostdlib",
                "-mthumb",
                "-Wl,--build-id=none",
                "-T",
                str(root / "patch.ld"),
                "-o",
                str(elf),
                str(root / "patch.S"),
            ],
            check=True,
            capture_output=True,
        )
        nm = subprocess.run(
            ["arm-linux-gnueabihf-nm", str(elf)],
            check=True,
            capture_output=True,
        ).stdout.decode()
        got = None
        for line in nm.splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[2] == sym:
                got = int(parts[0], 16)
                break
        if got != want_va:
            raise SystemExit(
                f"linker placed {sym} at {got and hex(got)}, expected {want_va:#x} "
                f"(nm:\n{nm})"
            )
        return subprocess.run(
            [
                "arm-linux-gnueabihf-objcopy",
                "-O",
                "binary",
                "-j",
                ".text",
                str(elf),
                "/dev/stdout",
            ],
            check=True,
            capture_output=True,
        ).stdout


def build_hook(base: int) -> bytes:
    hook_va = base + HOOK_OFF
    tramp_va = base + TRAMPOLINE_OFF
    ld = f"SECTIONS {{ . = {hook_va:#x}; .text : {{ *(.text*) }} }}\n"
    asm = f"""\
.syntax unified
.thumb
.global _hook
_hook:
    b.w {tramp_va:#x}
"""
    raw = _link_bytes(ld, asm, "_hook", hook_va)
    if len(raw) != 4:
        raise SystemExit(f"hook size {len(raw)}, expected 4")
    return raw


def build_trampoline(base: int) -> bytes:
    tramp_va = base + TRAMPOLINE_OFF
    ld = f"SECTIONS {{ . = {tramp_va:#x}; .text : {{ *(.text*) }} }}\n"
    asm = f"""\
.syntax unified
.thumb
.global autogo_eof
autogo_eof:
    ldr   r1, [r4, #0x10]        @ this completion's byte count
    cmp   r1, #{PKT}
    bhs   not_eof                @ full chunk -> keep receiving

    ldr   r6, [r5, #{PAYLOAD_ENTRY_OFF}]  @ payload entry (0x80000000, ARM)
    blx   {CACHE_FLUSH:#x}       @ flush D+I caches (ARM fn)
    mov   r1, r6
    blx   r1                     @ jump to payload (ARM entry); return -> not_eof

not_eof:
    movs  r0, #1
    strb  r0, [r5]               @ ctx->done = 1
    add.w r0, r5, #0xc
    pop.w {{r4, r5, r7, lr}}
    b.w   {USB_CONTINUE:#x}
"""
    raw = _link_bytes(ld, asm, "autogo_eof", tramp_va)
    if len(raw) > TRAMPOLINE_MAX:
        raise SystemExit(f"trampoline size {len(raw)} > {TRAMPOLINE_MAX}")
    return raw


def verify_patch(data: bytes, base: int) -> None:
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    insns = list(cs.disasm(data[HOOK_OFF : HOOK_OFF + 4], base + HOOK_OFF))
    if len(insns) != 1 or insns[0].mnemonic != "b.w":
        raise SystemExit(f"hook not b.w: {insns!r}")
    m = re.search(r"#(0x[0-9a-f]+)", insns[0].op_str)
    if not m or int(m.group(1), 16) != base + TRAMPOLINE_OFF:
        raise SystemExit(f"hook target wrong: {insns[0].op_str}")

    tramp = list(
        cs.disasm(
            data[TRAMPOLINE_OFF : TRAMPOLINE_OFF + TRAMPOLINE_MAX],
            base + TRAMPOLINE_OFF,
        )
    )
    print("  eof trampoline:")
    for insn in tramp[:18]:
        print(f"    {insn.address:#010x}  {insn.mnemonic} {insn.op_str}")
    blx_imm = []
    blx_reg = []
    for insn in tramp:
        if insn.mnemonic == "blx":
            if insn.op_str.startswith("#"):
                m2 = re.search(r"#(0x[0-9a-f]+)", insn.op_str)
                if m2:
                    blx_imm.append(int(m2.group(1), 16))
            elif insn.op_str.startswith("r"):
                blx_reg.append(insn.op_str)
    if CACHE_FLUSH not in blx_imm:
        raise SystemExit(f"trampoline missing blx -> CACHE_FLUSH: {blx_imm!r}")
    if not any("r1" in x for x in blx_reg):
        raise SystemExit(f"trampoline missing blx r1 (payload jump): {blx_reg!r}")


def patch_autogo(data: bytearray, base: int = IBOOT_BASE) -> dict:
    tramp = build_trampoline(base)
    hook = build_hook(base)

    cur = bytes(data[HOOK_OFF : HOOK_OFF + HOOK_LEN])
    if cur != HOOK_ORIG and cur != hook:
        raise SystemExit(
            f"unexpected bytes @ {HOOK_OFF:#x}: {cur.hex()} "
            f"(expected {HOOK_ORIG.hex()})"
        )

    # Allow refresh of an already-patched cave.
    cave = data[TRAMPOLINE_OFF : TRAMPOLINE_OFF + len(tramp)]
    if any(b not in (0, 0xFF) for b in cave) and cur == HOOK_ORIG:
        raise SystemExit(f"cave @ {TRAMPOLINE_OFF:#x} is not empty")

    data[TRAMPOLINE_OFF : TRAMPOLINE_OFF + len(tramp)] = tramp
    data[HOOK_OFF : HOOK_OFF + HOOK_LEN] = hook
    verify_patch(data, base)
    return {"hook": HOOK_OFF, "trampoline": TRAMPOLINE_OFF, "tramp_size": len(tramp)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", type=Path)
    ap.add_argument("output", type=Path)
    args = ap.parse_args()

    data = bytearray(args.input.read_bytes())
    base = iboot_base(data)
    if base != IBOOT_BASE:
        raise SystemExit(f"unexpected image base {base:#x} (want {IBOOT_BASE:#x})")
    info = patch_autogo(data, base)
    args.output.write_bytes(data)

    print(f"wrote {args.output}")
    print(f"  hook: {info['hook']:#x} -> tramp {info['trampoline']:#x} ({info['tramp_size']} bytes)")
    print("  EOF (<0x8000): flush caches, blx payload @ [ctx+8]=0x80000000 (ARM)")
    print("  full chunk: stock USB_CONTINUE path")
    return 0


if __name__ == "__main__":
    sys.exit(main())
