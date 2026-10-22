# Boot chain on the A5 (iPad 2, k93ap)

## Stock chain (for reference)

```
SecureROM (BootROM, in mask ROM — checkm8 lives here)
  → iBSS (DFU/recovery mode bootloader)
  → iBEC (recovery bootloader)
  → iBoot (normal boot) → XNU kernel → iOS
```

Apple's SecureROM verifies every stage. We never modify anything on the NAND;
we only replace what runs **in RAM**, per boot.

## Linux chain

```
host PC ──USB── iPad 2 (jailbroken iOS 9.3.5 running)
                 │  kDFU: entered from the jailbroken OS via tweak (software-only)
                 ▼
               pwned DFU  (same USB DFU mode, signature checks defeated)
                 │  host uploads patched iBSS/iBEC (primepwn → autogo chain,
                 │  regenerated from the user's own IPSW — no Apple binaries
                 │  are distributed)
                 ▼
               patched iBEC runs a staging bundle from RAM
                 ▼
               Linux 6.12 zImage + k93ap.dtb + Alpine initramfs
                 ▼
               shell on the glass (tty0), USB console + CDC ECM network
```

Hold **power + home** at any point → the iPad boots back into iOS, untouched.

## Ways into pwned DFU

| Route | Hardware | Notes |
|---|---|---|
| **kDFU from jailbreak** | none (software-only) | recommended; Cascadia: `./cascadia flash --kdfu`; Legacy-iOS-Kit also supports jailbroken/kDFU on A5 |
| kloader (ios-kexec-utils) | none | reboots a jailbroken device straight into a custom payload, skipping DFU entirely |
| checkm8-a5 via Raspberry Pi Pico | ~$5 Pico | only needed for pwned DFU from a *non-jailbroken* device (restores/downgrades) |
| checkm8-a5 via Arduino + USB host shield | ~$15–30 | same, older method |

A plain PC cannot pwn an A5 over USB by itself (BootROM USB timing) — that is
why the Pico exists. We don't need it: see
[docs/a5-software-only-bypass.md](docs/a5-software-only-bypass.md).

## After pwned DFU: two boot paths (from iBSSloader/Cascadia)

1. **ACE staging-bundle path** — patched iBSS + autogo iBEC + staging bundle
   containing the Linux image. The autogo hook patches an address inside one
   specific iBEC build, so the chain is **pinned to a board + iOS version**
   (Cascadia pins p105ap on iOS 8.4.1 / 12H321). For k93ap we must pick the
   iOS version and locate the hook in that iBEC — see the porting notes.
2. **LIK `bootx` path** — Legacy-iOS-Kit's ramdisk + `bootx` boot. Uses saved
   IPSW artifacts; no autogo iBEC hook needed.

Alternatives that boot a custom **iBoot** on 32-bit devices (useful if we want
the stock iBoot UI with signature checks off):

- [iBoot32Patcher](https://github.com/iH8sn0w/iBoot32Patcher) (iH8sn0w) —
  universal 32-bit iBoot patcher, iPhone OS 2 → iOS 10 (covers k93ap's iBoot).
- [checkm8_bootkit](https://github.com/NyanSatan/checkm8_bootkit) (NyanSatan) —
  boots arbitrary iBoot via ipwndfu's custom protocol on 32-bit platforms.

## What is NOT used

- **pongoOS** — arm64-only (A7+). Not applicable to the A5.
- **openiBoot** — ancient, no A5/iPad 2 support; superseded by the above.
- **gaster** (0x7ff) — a checkm8 implementation usable from Windows hosts;
  A10/A11-oriented, A5 still needs the Pico/kDFU.

## Regenerating the chain from your own IPSW

Cascadia's `./cascadia firmware` decrypts and patches iBSS/iBEC from the user's
own IPSW and verifies the result byte-for-byte. For k93ap we use the
iPad2,1 IPSW (e.g. 9.3.5 13G36 — and 8.4.1 if the chain pins to it, as the
p105 chain does). **Never commit the resulting Apple binaries** — they are
built locally (see .gitignore: `ipsw/`, `saved/`, `firmware/`).
