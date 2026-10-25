# ipad-rea — native Linux on the iPad 2 (Apple A5)

Port of [Project Cascadia](https://github.com/rzxvx/Project-Cascadia) — mainline
Linux 6.12 + Alpine on the A5 iPad mini 1 — to the **iPad 2** (iPad2,1 / k93ap /
S5L8942, currently on iOS 9.3.5).

Same idea as [HackiOS](https://hackiosx.dev/) running iOS 16 on Snapdragon
phones, in reverse: we run Linux on Apple's A5 hardware. iOS stays installed
and untouched; booting Linux is a RAM-only step you trigger from a jailbroken
iOS. Nothing is ever written to the iPad's NAND.

## Target hardware

| | iPad mini 1 (upstream) | iPad 2 (this port) |
|---|---|---|
| Model | iPad2,5 / A1432 | iPad2,1 (WiFi) |
| Board config | p105ap | k93ap |
| SoC | A5 S5L8942X | A5 S5L8942 (rev A) |
| Board platform | s5l8940x | s5l8940x (same family) |
| RAM | 512 MiB @ 0x80000000 | 512 MiB @ 0x80000000 |
| Display | 1024x768 (simplefb) | 1024x768 (simplefb) |
| WiFi/BT | BCM4334 (HSIC behind EHCI) | BCM4329 on **SDIO** (ADT wifi-chipset "43291", fw dir wifi/4329c0); BT BCM43291A0 on uart3 @ 3 Mbaud |
| Battery gauge | bq27540 (HDQ one-wire) | bq27540 on uart5 (confirmed from ADT) |

## Boot chain

```
iPad 2 on iOS 9.3.5, jailbroken (EverPwnage, untethered)
  │  software-only — no extra hardware
  ▼
kDFU (pwned DFU entered from the jailbroken device)
  ▼
patched iBSS/iBEC (primepwn / autogo chain, regenerated from your own IPSW)
  ▼
Linux 6.12 zImage + ipad2-k93ap.dtb + Alpine armv7 initramfs   (RAM only)
  ▼
shell on the glass + USB console/ethernet; hold power+home to return to iOS
```

pongoOS is **not** part of this chain — it is arm64-only; the A5 chain is
iBSSloader / checkm8_bootkit style. See [docs/bootchain.md](docs/bootchain.md).

## Software-only A5 bypass (no Raspberry Pi Pico)

Entering pwned DFU on A5 from a plain PC is not possible: the A5 BootROM USB
controller needs tighter timing than a general-purpose host manages, which is
why checkm8-a5 normally requires a Pi Pico or Arduino + USB host shield. But
from a **jailbroken** device you can enter pwned DFU purely in software:
**kDFU**. Project Cascadia's own quickstart uses exactly this
(`./cascadia flash --kdfu` — "No extra hardware at all").

Details: [docs/a5-software-only-bypass.md](docs/a5-software-only-bypass.md)

## Bonus: your jailbreak can be permanent too

[EverPwnage](https://github.com/LukeZGD/EverPwnage) is an **untethered**
jailbreak for 32-bit devices on iOS 7.0–9.3.6 — including the iPad 2 on
9.3.5/9.3.6 (iocaste untether). Sideload its IPA with **one command**
(`scripts/sideload-everpwnage.sh` — local anisette + AltServer-NG, no GUI tools
needed) with "Install Untether" enabled (default) and the jailbreak survives
reboots. It also provides the jailbroken state that kDFU needs for the Linux
boot chain.

This is the **primary** path to a permanent, software-only (no extra hardware)
jailbreak. Verified IPA staged at `build/jailbreak/EverPwnage-v2.0.2.ipa`
(re-fetch/verify: `scripts/fetch-jailbreak-ipas.sh`). Full step-by-step, plus
why the A5 DFU exploit can't run on a PC and a Phoenix fallback:
[docs/k93-permanent-jailbreak.md](docs/k93-permanent-jailbreak.md).

## Status / roadmap

- [x] Research: upstream identified (Project Cascadia, iBSSloader, Legacy-iOS-Kit)
- [x] Software-only A5 bypass identified (kDFU from jailbreak)
- [x] Extract k93ap ADT from the iPad2,1 IPSW → base DTS + diff (`scripts/extract-adt.sh`)
- [x] Finalize dts/ipad2-k93ap.dts — now **fully generated from the k93 ADT**
      (`scripts/gen-dts.sh` + `tools/gen_k93ap_dts.py`); deltas confirmed in
      [docs/porting-deltas.md](docs/porting-deltas.md)
- [ ] Adapt kernel config (config/k93ap.config) + apply Cascadia kernel patches
- [ ] Build Linux 6.12 armhf (needs arm cross-gcc + flex/bison — via Cascadia's docker image)
- [ ] Regenerate the iBSS/iBEC chain for k93ap (9.3.5 pinned; find the autogo hook in the k93 iBEC)
- [ ] Extract BCM4330 WiFi + digitizer firmware from the IPSW rootfs DMG
- [ ] Enter kDFU from the jailbroken 9.3.5, boot initramfs on hardware
- [ ] Alpine rootfs, USB ECM networking, touch, WiFi (BCM4330 on SDIO), desktop

## Safety

- Nothing is written to the iPad's NAND. Linux runs from RAM; hold
  power+home to boot back into iOS.
- The iBSS/iBEC chain is regenerated from **your own** IPSW; no Apple
  binaries are committed to this repo.
- Back up the iPad first. Tethered experiments can crash; worst case is an
  iTunes restore to 9.3.5 (still signed for iPad 2).

## Layout

```
dts/       ipad2-k93ap.dts — device tree (GENERATED from the k93 ADT)
tools/     gen_k93ap_dts.py — ADT JSON -> ipad2-k93ap.dts generator
config/    k93ap.config — kernel config fragment (from Cascadia p105ap)
loader/    stage1 loader (linux_boot_start.S/.c, linux-boot.ld) for kDFU autogo
patches/   k93/ — kernel delta patches on top of the Cascadia set
docs/      bootchain, software-only bypass, UART, porting deltas, references,
           k93-ibec-autogo (RE findings), k93-boot-linux (boot procedure)
boot/      boot-linux.sh — host-side kDFU boot script (the on-device step is
           Legacy iOS Kit's restore.sh --kdfu)
scripts/   fetch-upstreams, fetch-kernel-k93, extract-adt (IPSW -> decrypted ADT),
           gen-dts (ADT -> ipad2-k93ap.dts), build-chain-k93 (iBSS/iBEC patches),
           build-kernel-k93 (Linux 6.12 zImage), build-staging-k93 (dtb+loader+
           staging-bundle.bin), extract-firmware
rootfs/    Alpine build notes
build/, ipsw/, upstream/   gitignored working dirs (artifacts, IPSW, clones)
```

## References

See [docs/references.md](docs/references.md).
