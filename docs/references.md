# References

## Our direct base

- **Project Cascadia** — Native Linux on Apple A5 (iPad mini 1): mainline Linux
  6.12 + Alpine, touch, Wi-Fi, XFCE. DTS, kernel config, kernel patches, build
  scripts, boot chain. https://github.com/rzxvx/Project-Cascadia
- **iBSSloader** (teutekeune) — original iPad mini 1 Linux boot chain: ADT→DTS
  tooling, patched iBSS/iBEC, bare-metal probes, ACE vs LIK boot paths.
  https://github.com/teutekeune/iBSSloader

## Boot / exploit tooling

- **Legacy-iOS-Kit** (LukeZGD) — restore/downgrade/jailbreak legacy devices;
  checkm8-a5 (Pi Pico / Arduino), **kDFU** support for jailbroken A5 devices,
  sideloading on Linux. https://github.com/LukeZGD/Legacy-iOS-Kit
- **EverPwnage** (LukeZGD) — untethered jailbreak, 32-bit, iOS 7.0–9.3.6
  (iPad 2 on 9.3.5/9.3.6 via iocaste). https://github.com/LukeZGD/EverPwnage
- **checkm8-a5** (LukeZGD fork / a1exdandy port for S5L8940X/S5L8942X/S5L8945X)
  — pwned DFU for A5 with a Pi Pico or Arduino + USB host shield.
  https://github.com/LukeZGD/checkm8-a5 · https://github.com/a1exdandy/checkm8-a5
- **iBoot32Patcher** (iH8sn0w) — universal 32-bit iBoot patcher, iPhone OS 2 →
  iOS 10 (covers k93ap). https://github.com/iH8sn0w/iBoot32Patcher
- **checkm8_bootkit** (NyanSatan) — boot arbitrary iBoot on 32-bit platforms
  via ipwndfu's custom protocol. https://github.com/NyanSatan/checkm8_bootkit
- **ios-kexec-utils / kloader** (ramytuki) — reboot a jailbroken device into
  pwned DFU / another OS from userland. https://github.com/ramytuki/ios-kexec-utils
- **gaster** (0x7ff) — checkm8 implementation (Windows hosts; A10/A11-oriented).
  https://github.com/0x7ff/gaster
- **checkm8** (axi0mX) — the BootROM exploit (CVE-2019-8900), A5–A11.
  https://github.com/axi0mX/ipwndfu · https://en.wikipedia.org/wiki/Checkm8

## Kernel / userland

- **SoMainline linux-apple-resources** — arm64 kernel tree resources + guide
  (A7–A11; our armv7 build is separate but the docs are useful).
  https://github.com/SoMainline/linux-apple-resources
- **Alpine Linux** — the userland (armv7 minirootfs).
  https://alpinelinux.org/ · Cascadia: `scripts/build-alpine-rootfs.sh`
- **ipad-nixos** — reproducible kernel + userland builds for A7–A11 iPads.
  https://github.com/jacopone/ipad-nixos

## The analogous port (iOS on Android)

- **HackiOS / ios-sweet** — real iOS 16 on Snapdragon phones.
  https://hackiosx.dev/ · https://github.com/ezuy/ios-sweet (community mirrors)

## Trackers / wikis

- **ipadlinux.org** — community tracker for Linux on iPads.
  https://ipadlinux.org/
- **The Apple Wiki** — 30-pin connector, checkm8-a5, iBoot32Patcher, gaster.
  https://theapplewiki.com/
- **ios.cfw.guide** — checkm8-a5 usage, Phoenix/p0laris install guides.
  https://ios.cfw.guide/
- **ipsw.me / ipsw.io** — iPad2,1 firmware info + downloads.
  https://ipsw.me/iPad2,1
- **The iPhone Wiki — Durango 8L1 (iPad2,1)** — firmware file names + IV/keys
  (iBSS.k93ap.RELEASE.dfu, kernelcache.release.k93).
  https://www.theiphonewiki.com/wiki/Durango_8L1_(iPad2,1)
