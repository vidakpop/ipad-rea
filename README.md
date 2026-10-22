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
| WiFi/BT | BCM4334 (HSIC behind EHCI) | BCM4330 (bus TODO from ADT) |
| Battery gauge | bq27540 (HDQ one-wire) | likely same — verify from ADT |

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
9.3.5/9.3.6 (iocaste untether). Sideload its IPA (Sideloadly / PlumeImpactor,
or Legacy-iOS-Kit on Linux) with "Install Untether" enabled (default) and the
jailbreak survives reboots. It also provides the jailbroken state that kDFU
needs for the Linux boot chain.

## Status / roadmap

- [x] Research: upstream identified (Project Cascadia, iBSSloader, Legacy-iOS-Kit)
- [x] Software-only A5 bypass identified (kDFU from jailbreak)
- [ ] Extract k93ap ADT from the iPad2,1 IPSW → generate base DTS, diff vs p105ap
- [ ] Finalize dts/ipad2-k93ap.dts (started from adapted p105ap.dts, deltas marked)
- [ ] Adapt kernel config (config/k93ap.config) + apply Cascadia kernel patches
- [ ] Build Linux 6.12 armhf
- [ ] Regenerate the iBSS/iBEC chain for k93ap (pick + document the pinned iOS version)
- [ ] Enter kDFU from the jailbroken 9.3.5, boot initramfs on hardware
- [ ] Alpine rootfs, USB ECM networking, touch, WiFi (BCM4330), desktop

## Safety

- Nothing is written to the iPad's NAND. Linux runs from RAM; hold
  power+home to boot back into iOS.
- The iBSS/iBEC chain is regenerated from **your own** IPSW; no Apple
  binaries are committed to this repo.
- Back up the iPad first. Tethered experiments can crash; worst case is an
  iTunes restore to 9.3.5 (still signed for iPad 2).

## Layout

```
dts/       ipad2-k93ap.dts — device tree (adapted from Cascadia p105ap)
config/    k93ap.config — kernel config fragment (from Cascadia p105ap)
docs/      bootchain, software-only bypass, UART, porting deltas, references
boot/      kDFU entry notes + host-side boot script
scripts/   fetch-upstreams, extract-adt, build-kernel, extract-firmware
rootfs/    Alpine build notes
```

## References

See [docs/references.md](docs/references.md).
