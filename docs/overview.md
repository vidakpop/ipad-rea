# Overview — what exists, and what this project is

## The landscape (who has done the analogous thing)

| Project | What it runs | On what | Relevance |
|---|---|---|---|
| [HackiOS / ios-sweet](https://hackiosx.dev/) | real iOS 16 (XNU + iPhone userland) | Snapdragon Android phones (Redmi, POCO, OnePlus, Oppo…) | the "iOS 16 on an Oppo" project — proof that a hobbyist team can port a whole OS to foreign hardware |
| [Project Sandcastle](https://en.wikipedia.org/wiki/Project_Sandcastle) (Corellium, 2020) | Android 10 | iPhone 7 (A10) | first big "other OS on iPhone", checkra1n-based |
| [postmarketOS](https://postmarketos.org/) | Alpine Linux | iDevices A8 and newer | touch-optimized distro; A5 not covered |
| [ipad-nixos](https://github.com/jacopone/ipad-nixos) | NixOS | iPads A7–A11 via checkm8 | reproducible kernel+userland build for iPads |
| [Linux on A7–A8X](https://konradybcio.github.io/) (SoMainline, konradybcio) | mainline Linux | iPhone 5S–7 era | the arm64 kernel tree + resources |
| **Project Cascadia** (rzxvx) | **mainline Linux 6.12 + Alpine, XFCE, touch, Wi-Fi** | **iPad mini 1 (A5, p105ap)** | **our direct base — same SoC family as the iPad 2** |
| iBSSloader (teutekeune) | original A5 Linux boot chain | iPad mini 1 (p105ap) | ADT→DTS tooling, patched iBSS/iBEC, bare-metal probes; Cascadia builds on it |
| [ipadlinux.org](https://ipadlinux.org/) | tracker | all iPads | community index + compatibility news |

## Why the iPad 2 is a realistic target

- The A5 BootROM is permanently vulnerable to **checkm8** (CVE-2019-8900).
- The iPad 2 and iPad mini 1 share the **s5l8940x** platform family
  (S5L8942 rev A vs S5L8942X — a die revision, not a different SoC).
- Cascadia has already solved the hard A5 problems: a custom interrupt
  controller driver (AIC1), a working system tick, the Samsung-derived UART,
  USB gadget networking, touch, Wi-Fi, battery gauge, power-off.
- The iPad 2 differs from the mini 1 mostly in board-level details
  (panel, digitizer, WiFi chip), not in the SoC.

## What "reverse engineering" means for this port

Not much black-box RE is needed — Apple ships most of the answers:

1. **Apple Device Tree (ADT)** — the hardware description (MMIO addresses,
   GPIO map, buses) is inside the IPSW as `DeviceTree.k93ap.*.im4p`.
   Extract, decrypt, convert to DTS with iBSSloader/Cascadia tooling.
2. **iBEC/iBSS patching** — the boot chain patches Apple's own bootloader
   images, regenerated from your own IPSW (Cascadia verifies byte-for-byte).
   The autogo hook address is pinned per board+iOS build; for k93ap we pick
   the iOS version and find the hook address in that iBEC (Cascadia documents
   the method; `patch_bootx_handler.py` is in their attic).
3. **Digitizer** — brought up the way iOS does it, recorded from iOS's driver
   trace on the jailbroken device; firmware extracted from the IPSW.
4. **WiFi** — BCM4330 firmware + NVRAM extracted from the IPSW; the bus
   (SDIO vs HSIC) is read from the ADT.

The kernel side is mainline Linux 6.12 (armv7) plus Cascadia's small patch set
(ARCH_APPLE_S5L, AIC1 irqchip, Samsung serial tty, Apple S5L USB PHY).
