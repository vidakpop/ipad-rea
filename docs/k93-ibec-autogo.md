# k93 (iPad 2) iBEC autogo — reverse-engineering notes

Goal: patch `iBEC` (iBoot-2817, 13G36, iPad2,1) so that after a Recovery/DFU
bulk file upload finishes, iBEC flushes caches and jumps to the uploaded
payload at `0x80000000` — the k93 analog of Project-Cascadia's
`patch-ibec-autogo.py` (p105). This is the "ACE autogo" half of the kDFU boot
chain: once the device is in kDFU (software-pwned DFU, entered via the
EverPwnage/kDFU on-device tweak), the host uploads `iBSS.patched` then
`iBEC.autogo` (plain img3), and the patched iBEC receives the staging bundle
(loader + zImage-dtb) and jumps into it.

Image base `0x9ff00000`; all VAs below = base + file offset. Built artifact:
`build/adt-k93ap/iBEC.k93.autogo` (see `tools/patch-ibec-autogo-k93.py`).

## The receive path

iBEC's DFU/Recovery file-receive arms **one** ep4 OUT bulk transfer:

* arm fn `0x9ff1fba0(mode, buf)` — wrapper `0x9ff1fb7c` calls it with
  `(2, 0x80000000)`. It resets `ctx+4 = -1`, stores `buf` to `ctx+8`,
  clears `ctx+0`, then (mode==2) sets `ctx+1 = 1` and arms the endpoint via
  `ep_recv(ep=4, buf=0x80000000, maxlen=0x4000000, cb=0x9ff1fc31)`
  (`0x9ff1f638`). `maxlen = 0x4000000` (64 MiB) — the transfer is *not*
  completed per-chunk by maxlen.
* `ep_recv` `0x9ff1f638(r0=ep, r1=buf, r2=maxlen, r3=cb)` allocates a
  0x1c-byte transfer struct and fills it:

  | off | field    |
  |-----|----------|
  | +0  | ep       |
  | +4  | buf      |
  | +8  | status/flag |
  | +0xc| maxlen   |
  | +0x10| byte count (per completion) |
  | +0x14| callback |

* completion callback = **file `0x1fc30`** (VA `0x9ff1fc30`, Thumb; pointer
  `0x9ff1fc31` stored at transfer+0x14). Structure:

  ```
  push {r4,r5,r7,lr}; add r7,sp,#8; mov r4,r0        ; r4 = transfer
  ldr  r0,[r4,#8]; cmp r0,#0; bne <err 0x9ff1fd08>   ; status
  ldr  r1,[r4,#0x10]; cmp r1,#4; bne <data 0x9ff1fc76>
  ; count==4: 4-byte command dispatch (magic [buf]==0xfb, [buf+3]==0xfa, tbb)
  <data 0x9ff1fc76>:
  ldr  r0,[pc,#0x88]; movs r2,#0; bl 0x9ff32f1c       ; log/setenv "filesize"
  ldr  r5,[pc,#0x78]                                 ; r5 = ctx = 0x9ff4b750
  ldr  r0,[r4,#0x10]; str r0,[r5,#4]                 ; ctx+4 = count
  add.w r0,r5,#0x1c; bl 0x9ff1b988                   ; file_write(ctx+0x1c)
  movs r0,#1; strb r0,[r5]                           ; ctx+0 = 1   <-- HOOK
  add.w r0,r5,#0xc; pop.w {r4,r5,r7,lr}; b.w 0x9ff1c760
  ```

* ctx struct (`0x9ff4b750`): `+0` done-flag byte, `+1` mode, `+4` count,
  `+8` **payload entry = receive buffer = `0x80000000`**, `+0xc` sub-struct,
  `+0x1c` file-write arg.

## Constants (all RE-verified)

| constant       | value        | how found |
|----------------|--------------|-----------|
| HOOK_OFF       | `0x1fc8c`    | `movs r0,#1; strb r0,[r5]` tail of callback data path |
| HOOK_ORIG      | `01 20 28 70`| bytes at 0x1fc8c |
| TRAMPOLINE_OFF | `0x1a4`      | 92 B unreferenced zero padding (see below) |
| CACHE_FLUSH    | `0x9ff1d358` | ARM no-arg flush-all (see below) |
| USB_CONTINUE   | `0x9ff1c760` | stock tail-call target (re-arms next transfer) |
| PKT            | `0x8000`     | irecovery `-f` chunk size (see below) |
| payload entry  | `[r5+8]` = `0x80000000` (ARM state, bit0 clear) | ctx+8 |

### CACHE_FLUSH = 0x9ff1d358 (ARM mode)

The CP15/cache-maintenance bank (ARM mode) at `0x9ff1d170`–`0x9ff1d388`:

```
0x9ff1d170  clean D by MVA x8 (256B), DMB, bx lr
0x9ff1d1b4  invalidate D by MVA x8, DMB, bx lr
0x9ff1d1f8  clean+invalidate D by MVA x8, DMB, bx lr
0x9ff1d23c  clean entire D by set/way loop, DMB, bx lr
0x9ff1d26c  clean+invalidate entire D by set/way loop, DMB, bx lr
0x9ff1d29c  invalidate entire D by set/way loop, DMB, bx lr
0x9ff1d344  mov r0,#0; ICIALLU (c7,c5,0); DSB; ISB; bx lr
0x9ff1d358  stmdb sp!,{lr}; bl 0x9ff1d23c; bl 0x9ff1d344; ldm sp!,{lr}; bx lr
0x9ff1d36c  mrc/mcr SCTLR + isb (toggle MMU), bx lr
```

`0x9ff1d358` = **flush all caches** (clean whole D-cache by set/way, then
invalidate whole I-cache with DSB+ISB). No args; clobbers r0-r2 only
(r4-r7 preserved). This is the exact analog of p105's `CACHE_FLUSH=0x9FF2134C`.
It is ARM mode, so the Thumb trampoline calls it with `blx`.

### Cave = file 0x1a4..0x200 (VA 0x9ff001a4), 92 bytes

Zero padding between the boot halt-loop (`0x9ff001a0`: `b .`) and .rodata
(version strings at `0x9ff00200`). Verified safe:

* loaded (inside image `[0, 0x47e80)`), not `.bss` (bss clear covers
  `0x9ff47e80+`; image linked size `0x47e80` from the boot relocate loop);
* never executed (boot halts at `0x9ff001a0`, calls main at `0x9ff00b35`);
* **0 pointer references** anywhere in the image;
* executability of padding caves is proven by p105 (its cave `0x43e0e` runs).

Rejected caves: `0x247`/`0x28f` (zero tails of 64-byte version-string slots —
live buffers), `0x44b69` (87 B zero gap inside a live HW-register descriptor
table, referenced at `0x9ff1b154`), `0x46acc` (1332 B = start of a live global /
`.bss`, referenced at `0x9ff00338`).

### Chunk size / EOF test

`irecovery -f` (`irecv_send_file` → `irecv_send_buffer`) sends the file as
`0x8000`-byte `libusb_bulk_transfer` chunks to the OUT endpoint (chunk stride
`0x8000` from `mov $0x8000,%eax` + `imul %r14d` in `irecv_send_buffer`).
The completion callback therefore fires once per `0x8000` chunk; only the final
(short or zero-length) chunk reports `[transfer+0x10] < 0x8000`. The EOF test
`count < 0x8000` is the same one proven on p105 hardware (Cascadia boots an
11 MB staging bundle with it). It is robust to both per-chunk and
aggregate-until-short-packet completion, provided the final completion is
short — **so pad the staging bundle to a size that is NOT a multiple of
`0x8000`** (handled in the bundle builder).

## The patch

`tools/patch-ibec-autogo-k93.py` (run inside the `cascadia-build` docker image
for `arm-linux-gnueabihf-gcc`):

* hook: file `0x1fc8c` `01 20 28 70` -> `b.w 0x9ff001a4`
* trampoline (Thumb) at `0x9ff001a4` (34 bytes):

```
ldr   r1,[r4,#0x10]     ; this completion's byte count
cmp.w r1,#0x8000
bhs   not_eof           ; full chunk -> keep receiving
ldr   r6,[r5,#8]        ; payload entry 0x80000000 (ARM)
blx   0x9ff1d358        ; flush D+I caches (ARM fn)
mov   r1,r6
blx   r1                ; jump to payload (ARM entry); return -> not_eof
not_eof:
movs  r0,#1
strb  r0,[r5]           ; ctx->done = 1
add.w r0,r5,#0xc
pop.w {r4,r5,r7,lr}
b.w   0x9ff1c760        ; USB_CONTINUE
```

The patch is surgical: only `0x1a4..0x1c6` (trampoline) and `0x1fc8c..0x1fc90`
(hook) differ from `iBEC.k93.patched`; image size stays `0x48000`.

Gotcha: the trampoline/hook must be linked with `-Wl,--build-id=none` —
otherwise the linker emits a 0x24-byte `.note.gnu.build-id` before `.text`,
shifting the entry symbol and corrupting the PC-relative encodings. The
patcher also asserts (via `nm`) that the entry symbol lands on its exact VA.

## Status

* Host-side: patch builds, verifies by disassembly, byte-diff is exactly the
  two regions above. DONE.
* On-hardware: NOT yet run. Requires the device in kDFU (user triggers the
  kDFU tweak on-device), then host-side DFU upload of `iBSS.patched` and
  `iBEC.autogo` (plain img3), then `irecovery -f staging-bundle.bin`.
* Open items to confirm on hardware: payload entry is ARM (match the loader's
  `.arm` entry), EOF fires on the final short chunk (pad bundle off a
  `0x8000` multiple), and the FB/display init in the stage1 loader.
