# Alternative operating systems on the iPad 2 (iPad2,1 / K93AP / S5L8940X / A5)

Research date: **2026-11-15**. Device under investigation: Apple iPad 2 Wi-Fi, model **iPad2,1**, board **K93AP**, SoC **S5L8940X (CPID 0x8940)**, BDID 04, iBoot-838.3-era 32-bit armv7 platform, currently **iOS 9.3.5**, owner pursuing a host-only checkm8 DFU exploit.
Question: *"Assuming checkm8 succeeds and gives full unsigned code execution through pwned DFU — can we flash Linux or any other non-iOS OS instead?"*

---

## VERDICT (honest, short)

**1. Linux — YES, but only in one place, and it is new.** As of 2026 there is exactly one Linux port to the Apple A5, and it is **Project Cascadia** ([github.com/rzxvx/Project-Cascadia](https://github.com/rzxvx/Project-Cascadia), created **2026-08-11**, last push **2026-11-08**, 124★ as of 2026-11-15). It boots **mainline Linux 6.12** on the A5, has a **complete device tree and an experimental bring-up for the iPad 2 specifically** (`devices/a5/dts/k93ap.dts`, `devices/a5/docs/k93-bringup.md` — "Hardware tested: iPad2,1, S5L8940 / CPID 8940, BDID 04, K93AP"), and on the sibling iPad mini 1 (same SoC family, S5L8942X) it already runs a full XFCE desktop with touch, Wi-Fi, Bluetooth, audio, and a working OpenGL-capable GPU stack. **None of it is in mainline** — it is an out-of-tree patch set on Linux 6.12. **What you get on the iPad 2 is a RAM-only boot: root shell over USB, framebuffer console, USB networking, an Alpine rootfs — but no touch, no Wi-Fi, no audio, no persistent installation, nothing written to NAND.** "Flashing" Linux to the iPad 2's NAND — replacing iOS — **does not exist in any published tree** (persistent NAND storage is still open even upstream; latest A5 commit, 2026-11-08: *"a5: stage 2 knows a root on the NAND"*).

**2. Android — NO.** Project Sandcastle is the only Android-for-iPhone project and it supports **only the A10 devices: iPhone 7, 7 Plus, iPod touch 7** ([projectsandcastle.org/status](https://projectsandcastle.org/status): "these builds are only supported for iPhone 7 / 7+ and the iPod touch 7"). The A5/iPad 2 was never claimed, and no A5 kernel/device-tree for Android exists anywhere.

**3. Every other OS — NO.** No NetBSD port to any Apple mobile SoC (only Apple-silicon Macs, added Aug 2021). No FreeBSD port to Apple mobile hardware at all. pongoOS is arm64-only and explicitly does not run on the A5. No RTOS/bare-metal demos for S5L8940X were found. Windows: never applicable.

**4. The premise itself — host-only checkm8 for A5 DFU — is a documented dead end**, confirmed independently by three sources (Cascadia's boot research, ElcomSoft's forensic-tool engineering note, and the Legacy-iOS-Kit wiki). Every working A5 pwned-DFU path in existence uses either a **≈$5 Raspberry Pi Pico (RP2040)** acting as the USB host, an **Arduino + MAX3421E USB host shield**, or **kDFU entered from the already-jailbroken iOS** (no hardware at all). ElcomSoft, a company with every incentive to make it work from a PC, writes that software-only A5 pwn is "**unfeasible or plain impossible**" and ships a Pi Pico firmware (`picom8.uf2`) with their commercial tool.

**What the owner should do with this device:**
- **Save OTA SHSH blobs 6.1.3 and 8.4.1 today** (Legacy-iOS-Kit → "Save OTA Blobs") — per-ECID, saved offline, immune to future signing flips.
- **Untethered jailbreak 9.3.5 with EverPwnage** ([github.com/LukeZGD/EverPwnage](https://github.com/LukeZGD/EverPwnage), supports "A5(X) devices: iPhone 4S; iPad 2, 3, mini 1", uses iocaste untether for 9.3.5/9.3.6).
- **Boot Cascadia Linux 6.12 RAM-only from the jailbreak via kDFU** (this is exactly what the owner's own `ipad-rea` repo is: a port of Cascadia to k93ap) — or get a Pi Pico for the non-jailbroken/DFU-first path.
- **Skip the host-only checkm8 quest** — after weeks of effort the evidence says it cannot succeed; a $5 board or the software-only kDFU path solves it.
- Optionally **downgrade to 6.1.3 or 8.4.1 first** (still OTA-signed by Apple as of 2026-11; works per community reports as recently as this month) if a snappier, more tweak-friendly iOS is the goal.

---

## 1. LINUX

### 1.1 The complete history of the "Linux on Apple iDevices" question (and why A5 was a blind spot)

| Era | Project | What it supported | Status |
|---|---|---|---|
| 2001–2009 | **iPodLinux** (zipot & al., [ipodlinux.org](http://www.ipodlinux.org/)) | μClinux on **click-wheel iPods** (1st–5th gen etc.); never any iOS device ([Wikipedia](https://en.wikipedia.org/wiki/IPodLinux), [Apple Fandom wiki](https://apple.fandom.com/wiki/IPod_Linux)) | Dead (~2009); the name often misleads people into thinking "Linux on iPad" was solved — it was not |
| 2008–2012 | **OpeniBoot / iphonelinux** (planetbeing/David Wang, [github.com/planetbeing/iphonelinux](https://github.com/planetbeing/iphonelinux), repo created 2008-05-24, last push 2023-07-09, 621★) | 2.6 Linux + OpeniBoot on **iPhone 2G/3G and iPod touch 1G** (fully); partial: iPhone 3GS, iPhone 4, touch 2G/4G, **original iPad (A4)** ([Wikipedia OpeniBoot](https://en.wikipedia.org/wiki/OpeniBoot), [iDroid-Project/openiBoot](https://github.com/iDroid-Project/openiBoot)) | Abandoned; **A5 (S5L8940) never ported** — even the "iPad" in its porting table was the 2010 iPad 1 (A4/S5L8930). A 2026 revival fork ([iProgramMC/openiBoot](https://github.com/iProgramMC/openiBoot)) still targets the same old hardware |
| 2008–2010 | **Android on iPhone** (planetbeing et al.,"[iDroid]") | Android on iPhone 2G/3G (via OpeniBoot); PCWorld Sept 2010: "iPhone Dev Team … Android on iPhone" | Historical; **no A5** |
| 2019-09-27 | **checkm8** (axi0mX, [github.com/axi0mX/ipwndfu](https://github.com/axi0mX/ipwndfu)) | BootROM exploit for **S5L8947x/8950x/8955x/8960x, T8002/T8004, T8010/T8011/T8015**; the README explicitly lists **s5l8940x, s5l8942x (A5), s5l8945x (A5X) only as "future SoC support"** — never implemented host-side | ipwndfu itself never got a host-side A5 exploit; checkm8 as a vulnerability covers A5–A11 (per axi0mX and BleepingComputer's 2019 article) |
| 2020-06 | **checkm8-a5** ([a1exdandy/checkm8-a5](https://github.com/a1exdandy/checkm8-a5), created 2020-06-28, single 2020 commit, 194★; fork [LukeZGD/checkm8-a5](https://github.com/LukeZGD/checkm8-a5), "more stable", pushed 2026-04-20) | "checkm8 port for S5L8940X/S5L8942X/S5L8945X based on **Arduino and MAX3421E-based USB Host Shield**" (plus, since 2024, **Raspberry Pi Pico UF2 firmware** via LukeZGD — see the [Legacy-iOS-Kit checkm8-a5 wiki](https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/checkm8-a5), Pico files at [Legacy-iOS-Kit-Keys releases](https://github.com/LukeZGD/Legacy-iOS-Kit-Keys/releases/download/a/checkm8-pico.zip)) | **The** A5 DFU exploit — deliberately hardware-assisted (see §4 below) |
| 2021–2025 | **checkm8_bootkit** ([NyanSatan/checkm8_bootkit](https://github.com/NyanSatan/checkm8_bootkit), created 2021-02-11, last push 2025-12-21, 75★) | "Boot arbitrary iBoot via ipwndfu's custom protocol on **32-bit platforms**"; supported SoCs list starts with **S5L8940X – Apple A5** (then 8942/8945/8947, A6, A6X, Haywire S5L8747X, S1/S1P/S2/T1, S3); also KBAG decryption + demote (JTAG) | The real "what to run after pwned DFU" tool for 32-bit |
| 2020 | **Project Sandcastle** (Corellium, [projectsandcastle.org](https://projectsandcastle.org/)) | **Android/Linux boot chain for A10 only** (iPhone 7/7+/iPod touch 7); status page: "only supported for iPhone 7/7+ and the iPod touch 7" | Beta; unrelated chip class; see §2 |
| 2022→ | **postmarketOS** | Apple arm64 devices via the **Apple Generic iDevice port** (pmOS MR !6733); mainline DTS support begins with **s5l8960x (A7)** ([torvalds/linux arch/arm64/boot/dts/apple](https://github.com/torvalds/linux/tree/master/arch/arm64/boot/dts/apple)) | The pmOS wiki has a page named [Apple iPad 2 (apple-k93)](https://wiki.postmarketos.org/wiki/Apple_iPad_2_(apple-k93)) — but it is a **stub: "This device is marked as not booting"**, "Pre-built images: no", "Mainline: no", contributor field still `User:CHANGE_ME` (page last edited 2025-09-14) |
| 2022→ | **iPad Air 2 (A8X)** port by Konrad Dybcio & Mark "quaack723" Broks — Linux 5.18, June 2022 ([Ars Technica](https://arstechnica.com/gadgets/2022/06/developers-get-linux-up-and-running-on-old-ipad-air-2-hardware/), [Wikipedia: Linux on Apple devices](https://en.wikipedia.org/wiki/Linux_on_Apple_devices)); grew into pmOS support and, as of Oct 2026, installable distro images for newer iPads (e.g. **Omarchy A/Orchard** on iPad 6, tracked at [ipadlinux.org](https://ipadlinux.org/)) | A8+. Nothing for A5 | Active, but wrong SoC |
| 2023→ | **Hoolock Linux** ([github.com/HoolockLinux](https://github.com/HoolockLinux)) — "Linux on Apple iPhone, iPad, iPod touch, Apple TV and iBridge with **A7-A11 or T2 SoC**"; A9-era work grew out of the markushalade "linux-on-iphone"/iPhone 6s experiment; A12/A13 work boots via the **usbliter8** exploit and m1n1 | A7+. Nothing for A5 | Active, experimental |
| **2026** | **Project Cascadia** ([rzxvx/Project-Cascadia](https://github.com/rzxvx/Project-Cascadia)) — "Native Linux on Apple Silicons (A5 - A13)" | **iPad mini 1 (S5L8942X): complete; iPad 2 (S5L8940X): experimental RAM shell; iPhone 11 (A13): near-complete; iPhone XR (A12): contributed/experimental** | **The first and only Linux port to the A5.** Created 2026-08-11 (project started May 2026 per README: "while looking for an existing Linux port for the iPad mini 1, I found nothing: postmarketOS stops at A8, Project Sandcastle targeted A10, and the A5 had been completely ignored"); 664 commits; last A5 commit 2026-11-08 |

Bottom line of the history table: **before 2026 there was literally nothing for S5L8940X.** The A5 was a blind spot because it is 32-bit (excluded from the A7+ port wave), its BootROM USB timing excluded host-only exploits (§4), and OpeniBoot-era enthusiasm died at the A4. Cascadia is new, aggressive, and — conveniently for this specific owner — its A5 tree already contains the iPad 2 target (`k93ap.dts`), and the owner's own repository (`ipad-rea`) is the focused iPad-2 port of it.

### 1.2 What Cascadia actually achieves on the A5 (evidence)

From the root README and `devices/a5/README.md` ([link](https://github.com/rzxvx/Project-Cascadia/blob/main/devices/a5/README.md)):

- **iPad mini 1 (iPad2,5 / p105ap / S5L8942X)** — Linux 6.12 with: both CPU cores (SMP bring-up sequence reverse-engineered out of iOS 6.1's kernelcache, `docs/research/p105-smp-bringup.md`), multi-touch at 60 Hz (Z2 digitizer, protocol "the starting point … Project Sandcastle", `docs/research/p105-z2-boot.md`), **Wi-Fi BCM4334 on HSIC behind EHCI** (not SDIO — `wlan0` joins WPA2/open, DHCP, ~38/21 Mbit/s), Bluetooth via `hci_bcm` on UART1 (patchram out of the user's own IPSW), ALSA speakers, bq27540 battery gauge over HDQ, an **`apple-pmu-charger` / `apple-pmu-i2c` / `apple-pmu-wled`** PMU driver family (charging, backlight, poweroff), LIS3DSH accelerometer over I²C/IIO, PL310 L2 cache set up "the way iOS does it", **GPU: SGX543MP2 via a custom kernel DRM driver `drivers/gpu/drm/apple-sgx` that boots iOS's own GPU microkernel taken from the IPSW, plus a Mesa Gallium driver (GL 2.1 / GLES 2.0)** — XFCE runs GPU-accelerated ("dEQP-GLES2 16 859 of 16 950 run"), USB gadget via dwc2 (CDC-ACM console + CDC-ECM networking ~0.7 ms RTT, SSH/dropbear, apk), NFS root — and **iOS's own filesystem readable read-only from Linux** ("`ios mount`", custom PPN-NAND + LwVM + HFS+ drivers, `fs/hfsplus/decmpfs.c` for Apple's compressed files; the iOS **Data partition still does not mount** — per-file encryption).
- **iPad 2 Wi-Fi (iPad2,1 / K93AP / S5L8940X)** — the doc [`devices/a5/docs/k93-bringup.md`](https://github.com/rzxvx/Project-Cascadia/blob/main/devices/a5/docs/k93-bringup.md): *"Hardware tested: iPad2,1, S5L8940 / CPID 8940, BDID 04, K93AP…"* Verified on hardware:
  - Linux 6.12 reaches `/init`, interactive root shell over **CDC ACM** (`/dev/ttyACM0` on the host);
  - USB gadget enumerates (0525:a4aa), interrupts work (custom **AIC1 interrupt-controller driver** is fine on this chip);
  - **24 MHz watchdog counter at 0x3f103020** used as clocksource/delay-timer (CPU measured ~1 GHz); AIC timer as clockevent — there is a hard calibration dependency (`apple,s5l8940x-wdt-timer` node) without which the kernel hangs in `calibrate_delay()`; the "timer problem" (no working PMU/architected events on A5) is documented in `devices/a5/README.md#the-timer-problem`;
  - **simplefb 1024×768@32bpp, stride 4096, at 0x9f6fc000**, console 128×48 — in a 2026-10-18 "GUI4" run a full **Alpine 3.24.2 armv7** root (read-only squashfs + RAM overlay) ran Xorg 1.21 + TWM + xterm, verified by framebuffer capture — *software* rendering only;
  - **USB IP networking** host↔guest ping verified; no Internet routing in the diagnostic builds;
  - CPU MPIDR 0x80000900 (differs from the iPad mini's cluster topology) — device-specific DT work was needed;
  - **Not verified on K93: touch, Wi-Fi, audio, suspend, CPU1 (SMP), persistent storage, browser usability.** *"Do not inherit P105 support claims."*
  - No Apple firmware binaries ship in the repo; the boot chain is regenerated from the user's own `iPad2,1_8.4.1_12H321_Restore.ipsw` with public decryption material (`tools/k93-extract-firmware.py`, iBoot32Patcher); Ram-only, *"This does not mount or write internal storage."*
- The commit history through 2026-11-08 shows active work on both A5 boards: `a5: stage 2 knows a root on the NAND` (initramfs stage-2); `phy-apple-s5l-usb: bring up the PHY when the boot loader left it off`; `a5 desktop: build the patched packages as root…` (mesa/); `repo: move each device into devices/<soc> -- a5 (iPad mini 1, iPad 2)`.
- Independent corroboration: the [ipadlinux.org](https://ipadlinux.org/) tracker (updated Oct 2026) lists Project Cascadia — *"Runs Linux and Alpine on the original iPad mini, with a GPU-drawn touch desktop, Wi-Fi, and Bluetooth… Requires … either jailbroken iOS or a Raspberry Pi Pico. iOS stays installed. Linux isn't written to the device's storage."*
- Cascadia's own credits page names the exact prior art it is built on: **teutekeune** (iBSSloader — "the original work booting Linux on the iPad mini 1. Project Cascadia is built on it"; [teutekeune/iBSSloader](https://github.com/teutekeune/iBSSloader), created 2026-08-29), **axi0mX** (checkm8), **LukeZGD** (Legacy-iOS-Kit, EverPwnage, checkm8-a5 Pico firmware), **NyanSatan** (checkm8_bootkit, iBoot research), **iH8sn0w** (iBoot32Patcher), **Project Sandcastle** (Z2 multitouch driver/protocol).

### 1.3 Do "kernel + display + USB + storage drivers" exist for S5L8940X anywhere?

**Mainline: no.** Verified directly against `torvalds/linux`:
- `arch/arm/boot/dts/` (32-bit) has **no Apple SoC at all**;
- `arch/arm64/boot/dts/apple/` starts at **s5l8960x (A7)** — iPhone 5s (s5l8960x-n51/n53), iPad Air (j71/j72/j73), iPad mini 2/3 (j85/j86/j87) — then s8000/s8001/s8003 (A9), t7000/t7001 (A8), t8010/t8011 (A10/A10X), t8012 (T2), t8015 (A11), t8103 (M1), t8112 (M2), t8122, t8132, t8140 ([tree](https://github.com/torvalds/linux/tree/master/arch/arm64/boot/dts/apple)).
- Nothing named s5l8940/8942/8945 exists in any kernel.org tree. (Searched; the only "S5L" DTS in mainline start at the A7.)

**In a tree: yes — exactly one, Cascadia's**, as a patch set on **Linux 6.12** (`./cascadia a5 kernel` — "shallow clone of Linux, pinned to v6.12"; the patches visible in `devices/a5/patches/`: `arch_arm_Kconfig/Makefile`, `drivers_irqchip_Kconfig/Makefile` (the custom AIC1 driver), `drivers_tty_serial_samsung_tty.c` (the A5's Samsung-derived UART), `drivers/phy apple-s5l-usb`, plus the DRM/Mesa/NAND trees described above). Driver inventory relevant to the owner's question:

| Subsystem | What exists (Cascadia A5 tree) | Source |
|---|---|---|
| Interrupts | Custom **AIC1** irqchip driver ("The AIC problem — no interrupt ever reached the CPU" is solved and documented with a negative-results table) | `devices/a5/README.md` §Seven problems |
| Clocks/PMU | **No datasheet** — PMGR (power gating) reversed from iOS/iBEC behavior (`docs/research/p105-pmgr-gates.md`, `p105-xnu-pmgr-extract.md`); PMU handled by custom `apple-pmu-i2c` (PMIC is an Apple-custom part driven over I²C, not a "clockgen/SGPIO" device), `apple-pmu-charger`, `apple-pmu-wled` (backlight DAC). Clocksource = 24 MHz watchdog counter @ 0x3f103020; CPU frequency via read-only platform clock code (~1 GHz) | k93-bringup.md; a5 README |
| Memory | Fixed DDR mapping in DTS (512 MiB @ 0x80000000); RAM init is *not* done by Linux — **iBoot/iBEC initialize RAM before the kernel is handed over** (Linux is uploaded via irecovery after Apple's own boot stages) | k93-bringup.md; boot.md |
| Display | **Apple's display controller (CLCD) is initialized by Apple's own iBEC/iBoot; Linux inherits the framebuffer via `simplefb`** at 0x9f6fc000 (geometry confirmed by RAM probing — `docs/research/p105-fb.md`: scanout 0x9f6fc000, 768×1024 p105 / 1024×768 k93, 32bpp X8R8G8B8). **No native display-controller driver exists; rebooting into Linux without a prior iBEC display hand-off would leave the panel dark** | p105-fb.md; k93-bringup.md |
| USB | **dwc2** (mainline driver) in device mode: CDC-ACM console + CDC-ECM network on one port; `phy-apple-s5l-usb` PHY driver; **host mode (USB flash/keyboard) is on the roadmap but not done** — EHCI's only described child on A5 is the BCM4334 Wi-Fi over HSIC | a5 README (Current status, "USB host mode" unchecked) |
| Storage | **Read-only** driver for Apple's H2FMI + PPN NAND ("two Hynix packages … an I/O coprocessor does" the driving on iOS; command sequences read out of iBEC), serving LwVM partitions as NBD devices + HFS+/decmpfs: "iOS's own files, read-only, straight off the NAND". **Writing/own-root-on-NAND: not yet — latest commit is the WIP step.** iOS Data partition unreadable (per-file encryption) | a5 README §The NAND problem; commit 705fd31 |
| GPU | `drivers/gpu/drm/apple-sgx` + patched Mesa Gallium: OpenGL 2.1/EGL/ES2 on the **PowerVR SGX543MP2**, largely by replaying iOS's own init sequence and booting **iOS's GPU microkernel image** from the user's IPSW | a5 README; `docs/GPU.md` |
| Serial/UART | Samsung-derived UART, mainline `samsung_tty` driver, patched to bind; `earlycon=s3c6400,0x32500000`, 115200 8N1 on the dock/debug pads | feasibility.md; patches dir |
| SMP | CPU1 release sequence was found in **iOS 6.1's kernelcache** (PMGR +0x1008, +0x1214/+0x1220, AIC IPI_SEND); works on P105, **not yet verified on K93** | a5 README; p105-smp-bringup.md |

### 1.4 What bring-up would be required beyond what exists (for the owner's K93 work)

This is documented in Cascadia's research notes (`devices/a5/docs/research/`, incl. `feasibility.md`, `boot.md`, `boot-strategy.md`, `ADDRESSES.md`, `p105-*.md`) and in the K93 doc:
1. **Enter pwned DFU.** Either via checkm8-a5 hardware (Pico/Arduino — see §4) or **kDFU from the jailbroken device** (`kDFU` app from a jailbreak; Legacy-iOS-Kit "Enter pwned iBSS/kDFU mode for supported 32-bit devices"; Cascadia's own quickstart supports `--kdfu`).
2. **Regenerate the iBSS/iBEC chain from your own IPSW** (iBoot32Patcher + primes/autogo hooks; `./cascadia a5 firmware`; k93 tools consume an `iPad2,1_8.4.1_12H321_Restore.ipsw`). Note Cascadia's recorded pitfall: the Legacy-iOS-Kit-patched iBEC accepts `ramdisk`/`devicetree`/`bootx` but **`go`/`memboot` no-op on it**, which is why Cascadia ships its own autogo iBEC patch ("a5 loader: park every core but the boot CPU…", "stage 2 knows a root on the NAND").
3. **Upload and run**: `irecovery -f` the patched iBSS, then iBEC, then the staging bundle (kernel+DTB+initramfs), then `go` — with the UART console (0x32500000, 115200) attached if you want to see early printk; the K93 negative-result to watch for is the watchdog-timer calibration dependency (without the `apple,s5l8940x-wdt-timer` DT node the kernel hangs in `calibrate_delay()`, a documented hang on K93).
4. **Peripheral bring-up not yet done on K93** (owner's to-do): Wi-Fi (BCM4329 on **SDIO** on the iPad 2 — *different* from the iPad mini's HSIC BCM4334, per the `ipad-rea` README ADT extraction), touch, audio (the iPad mini's ALSA path exists as reference), SMP (different MPIDR affinity), and eventually persistence (NAND root).

### 1.5 Documentation that actually exists for S5L8940X

- **No public S5L8940 datasheet.** What the community has: the SecureROM (dumpable by checkm8 itself — `ipwndfu --dump-rom`), iBoot/iBEC Images (decrypted with public KBAG/GID research from the checkm8 era), the **Apple Device Tree (ADT)** inside each IPSW (the single best source of addresses — Cascadia and `ipad-rea` generate their DTS from it), board schematics/boardviews (**Cascadia's repo literally carries the iPad mini boardview `820-3243_Apple Ipad Mini A1455 - BoardView (.BVR)`**), and wiki pages: [K93AP (The iPhone Wiki)](https://www.theiphonewiki.com/wiki/K93AP) ("It makes use of … the A5 chip"), [K93AAP (The iPhone Wiki)](https://www.theiphonewiki.com/wiki/K93AAP) ("It uses the S5L8942, a revised version of the S5L8940"), [ipsw.me iPad2,1 BoardConfig info](https://ipsw.me/iPad2,1/info), [Apple Wiki on checkm8](https://theapplewiki.com/wiki/Checkm8_Exploit).
- **SecureROM/checkm8 research**: axi0mX's exploit + README (above), the thorough technical analysis by DSecurity ([habr.com/en/companies/dsec/articles/472762/](https://habr.com/en/companies/dsec/articles/472762/) — the article the checkm8-a5 Arduino port is built around, including the A5-specific "HOST2DEVICE control request without data phase" quirks), and ElcomSoft's applied write-ups ([checkm8: Unlocking and Imaging the iPhone 4s](https://blog.elcomsoft.com/2022/05/checkm8-unlocking-and-imaging-the-iphone-4s/)).
- **Everything else had to be (and was) re-derived by probing** — Cascadia keeps its wrong-turn notebooks in `devices/a5/docs/research/` (GPIO maps, NAND command timing, timer hunt, GPU init, SMP) which is, frankly, the best hardware doc for this SoC that exists anywhere.

---

## 2. ANDROID

**There is no Android for the A5, and there never was.**

- The only serious "Android on iPhone" effort in the modern era is **Project Sandcastle** (Corellium, announced March 2020). Its own status page ([projectsandcastle.org/status](https://projectsandcastle.org/status)): *"Currently, these builds are only supported for **iPhone 7 / 7+ and the iPod touch 7**."* Its homepage credits "Corellium, with special thanks to the PongoOS team and axi0mx" ([projectsandcastle.org](https://projectsandcastle.org/)).
- Contemporary coverage confirms A10-only scope and heavy limitations (Android 10 beta; broken multi-touch on iPod touch; relies on checkra1n/pongoOS, i.e. **A7–A11 arm64**): [Lowyat.NET](https://www.lowyat.net/2020/207193/project-sandcastle-run-android-on-iphone-7/), [todoandroid.es guide](https://en.todoandroid.es/you-can-now-run-android-10-on-some-iphones-thanks-to-project-sandcastle/), [r/jailbreak release thread](https://www.reddit.com/r/jailbreak/comments/fdg9ao/release_project_sandcastle_android_for_your_iphone/), [Hacker News](https://news.ycombinator.com/item?id=22493274). Wikipedia: *"Corellium's Project Sandcastle made it possible to run Android on an iPhone 7/7+ or an iPod Touch (7th generation) using the checkm8 exploit."* ([Linux on Apple devices](https://en.wikipedia.org/wiki/Linux_on_Apple_devices)).
- **Nothing for the A5 was ever claimed, and nothing exists**: Sandcastle's kernel work targets arm64 (A10), and there is no A5 device-tree, no A5 kernel ports, and no Android kernel drivers (display, touchscreen, BCM43xx SDIO Wi-Fi, SGX543 GPU) for S5L8940X in any public tree — the only A5-capable kernel tree in existence is Cascadia's, which contains no Android work.
- The historical Android-on-iPhone projects were the original iPhone/3G era (planetbeing's port, 2008–2010, [PCWorld](https://www.pcworld.com/article/512296/iphone_runs_android_hands_on.html), [Network World](https://www.networkworld.com/article/755250/linux-based-android-os-ported-to-iphone.html)) — S5L8900-class hardware, ~15 years before the A5's only Linux port existed at all. An iPad 2 is not reachable from any of this. In addition, the checkra1n toolchain that Sandcastle depends on never supported the A5 — its own site: **"Jailbreak for iPhone 5s through iPhone X, iOS 12.0 and up"** ([checkra.in](https://checkra.in/)) — the common "checkm8 covers A5–A11, so checkra1n supports the iPhone 4s" confusion is precisely addressed by BleepingComputer's 2019 explainer ([link](https://www.bleepingcomputer.com/news/apple/checkra1n-ios-jailbreak-gets-public-beta-update-with-fixes/)): the *exploit* covers A5–A11; the *jailbreak product* targeted 5s→X. (One Cascadia research note repeats the "checkra1n betas had 32-bit A5 support" myth — checkra1n's own release pages do not support that claim.)

---

## 3. OTHER OPERATING SYSTEMS

**NetBSD:** No port to any Apple mobile device exists. The only NetBSD/Apple-silicon support is **arm64 Macs (M1), added to NetBSD-current on Aug 30, 2021** ([wiki.netbsd.org/ports/evbarm/apple](https://wiki.netbsd.org/ports/evbarm/apple/)), which explicitly recommends the Asahi Linux installer; the platform list ([wiki.netbsd.org/ports](https://wiki.netbsd.org/ports/)) contains no iDevice/A-series Smartphone SoC target, and nothing for armv7 S5L8940X. r/NetBSD discussion reflects the same state ([link](https://www.reddit.com/r/NetBSD/comments/1ilny4z/how_is_apple_silicon_support/)).

**FreeBSD:** No support for Apple mobile hardware at all. From the FreeBSD community (Feb 2025, freebsd-questions): *"FreeBSD does not run on Apple hardware … but NetBSD does"* ([Google Groups thread](https://groups.google.com/g/ml-freebsd-questions/c/Ayf4eMlJ0os)). There is no FreeBSD armv7 port for S5L8940X, no driver set, no published attempt.

**pongoOS:** arm64-only pre-boot environment ([github.com/checkra1n/pongoOS](https://github.com/checkra1n/pongoOS)); Cascadia's own feasibility doc states "Run pongoOS / interactive shell — **No — AArch64 only, not on A5**" (`devices/a5/docs/research/feasibility.md`).

**Windows:** Not possible — historically (locked boot, no ARMv7 build with iBoot protocol support; [Apple Communities](https://discussions.apple.com/thread/7549218), [r/bootcamp](https://www.reddit.com/r/bootcamp/comments/mbvf0x/windows_on_ipad_2/)) and presently (the 2026 "Windows on iPad" experiments concern A10/A12-class iPads booted via checkm8/pongo/m1n1 chains, e.g. [Android Authority's iPad experiment](https://www.androidauthority.com/windows-ipad-3312314/) — arm64 iPads only).

**RTOS / bare-metal demos:** No public bare-metal RTOS (FreeRTOS, Zephyr, custom) port or demo targeting S5L8940X was found in any search over GitHub or the jailbreak-research space. The 32-bit bootkit world (checkm8_bootkit, iBSSloader) is about booting _Apple's_ iBSS/iBEC images, not third-party OS kernels.

**What people REALLY ran after pwned DFU on A5 (2019→2026):**
1. **downgrades and restores** — Legacy-iOS-Kit / odysseusOTA lineage: pwned iBSS + custom IPSWs, "Restore to signed OTA versions (iOS 8.4.1 and/or 6.1.3) on A5/A6 devices" ([README](https://github.com/LukeZGD/Legacy-iOS-Kit)), SHSH-blob restores, tethered boots ("Just Boot"; A5 needs checkm8-a5 hardware to boot a tethered downgrade per the [Restore/Downgrade wiki](https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/Restore-Downgrade));
2. **SSH ramdisks** and device utilities (Legacy-iOS-Kit "Boot SSH Ramdisk for supported 32-bit and 64-bit devices", onboard-blob dumps, hacktivation, NVRAM clears);
3. **custom iBSS/iBEC images** via checkm8_bootkit (NyanSatan, S5L8940X explicitly listed) and iBSSloader (teutekeune) — i.e., arbitrary *Apple-format* boot images, patched with iBoot32Patcher — including custom boot logos (iBoot image tooling, e.g. [LukeZGD/ibootim](https://github.com/LukeZGD/ibootim)) and verbose-boot images;
4. **jailbreak payloads/kits for 9.3.5** — historically Phoenix/3uTools-style semi-untethers, and since 2023-2026 **EverPwnage** (untethered, with **iocaste** for 9.3.5/9.3.6 by staturnzz; [repo](https://github.com/LukeZGD/EverPwnage));
5. **commercial forensics** — ElcomSoft iOS Forensic Toolkit 8 (Mac/Linux, **"passcode unlock and forensically sound checkm8 extraction of iPhone 4s, iPad 2 and 3"** using a Raspberry Pi Pico with their `picom8.uf2`; supports "A5 (S5L8940), A5 Rev A (S5L8942) and A5X (S5L8945)" — [ElcomSoft blog, May 2022](https://blog.elcomsoft.com/2022/05/checkm8-unlocking-and-imaging-the-iphone-4s/)); newer 2026 tools in the same niche (e.g. "tr4mpass"-style activation-lock tooling) also ride checkm8;
6. **dual-booting other *iOS* versions** (not other OSes): FourThree-iPad2 dual-boots iPad 2 to iOS 4.3.x ([repo](https://github.com/LukeZGD/FourThree-iPad2)); powdersn0w/DRA v6 make nearly **any iOS version** bootable on the A5 via restore-exploit chains (see §4);
7. **and, since May/August 2026: Linux** — Cascadia, on iPad mini 1 and (experimentally) iPad 2. That's the entire list.

---

## 4. THE COMPARATIVE ENDGAMES (ranked, with current viability)

**(b) OTA-SHSH downgrade to 6.1.3 / 8.4.1 — ALIVE. Do it now.**

- Mechanism: Apple's TSS servers still return signed **OTA aptickets** for legacy builds (request via `tsschecker --ota` with your ECID; Legacy-iOS-Kit automates "Save OTA Blobs" even with no device attached). OTA-signed versions per the Legacy-iOS-Kit wiki ([OTA-Downgrade](https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/OTA-Downgrade)): **iOS 6.1.3 for iPhone 4S and iPad 2 (except iPad2,4); iOS 8.4.1 for iPhone 4S, iPhone 5, iPad 2, iPad 3, iPad 4, iPad mini 1, iPod touch 5; iOS 10.3.3 for A7**. This is the odysseusOTA ([wiki-era origins, 2015](https://theapplewiki.com)) / Vieux ([MatthewPierson/Vieux](https://github.com/MatthewPierson/Vieux), created 2019-11, last push 2023-02, 812★, macOS-only) / [LucyVR1/OTA-Downgrade-iOS-8.4.1](https://github.com/LucyVR1/OTA-Downgrade-iOS-8.4.1) (created **2026-10-06**, a Windows 8.4.1 downgrader) lineage — the same method, still working.
- **2026 status specifically:** Legacy-iOS-Kit (pushed **2026-11-14**, 3195★) still documents OTA downgrades as a supported, "signed" path; r/LegacyJailbreak activity from this month reports **"Just downgraded my iPad 2 to iOS 6.1.3"** ([thread 1mmfgr3, ~Nov 2026](https://www.reddit.com/r/LegacyJailbreak/comments/1mmfgr3/how_to_downgrade_iphone_4s_to_613_using_shsh/)).
- **The July 2026 scare, with resolution:** on **2026-07-08** Apple stopped validating legacy OTA/IPSW versions — per @aaronp613's tracking the iPhone 4S (6.1.3/8.4.1 OTA; 9.3.5/9.3.6 IPSW), iPad 2 Wi-Fi+3G CDMA (iPad2,3), iPad mini cellular (iPad2,6), iPhone 5/5c, iPad 4 cellular etc. were affected ([9to5Mac, Jul 8 2026](https://9to5mac.com/2026/07/08/apple-stops-signing-ios-versions-for-several-older-iphones-and-ipads/), [Mactrast](https://www.mactrast.com/2026/07/apple-just-stopped-signing-ios-and-ipados-versions-for-these-older-iphones-and-ipads/)). **On 2026-07-09 3:28 p.m. ET Apple restored signing — "Apple has resolved the issue. All legacy devices are signed again"** (same sources, "[U: Signing restored]"). Note: **iPad2,1 (Wi-Fi) was not even in the unsigning list** (only cellular/baseband models were) — but the event proves Apple *can* flip these at will. Blobs saved to disk are yours forever (ECID-bound, offline, replayable via the custom-restore chain), so **save 6.1.3 and 8.4.1 blobs today**; also dump **iOS 7.x blobs** while you're at it (see powdersn0w below).
- Cost of the downgrade: your device stays on a downgrade-capable path **whether or not you have blobs**:
  - **Without blobs:** OTA restore (needs the still-alive Apple signing, or pre-saved blob), or **DRA v6** (iOS 6 restore-exploit by synackuk/Pingzi610 — "since iOS 6 is signed [for the supported devices], no existing blobs are required"; supported targets: **iPad 2 (all models except iPad2,4)**, iPhone 4S, iPod touch 4; untethered to anything up to **iOS 9.3.5**, [wiki](https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/DRA-v6)).
  - **With iOS 7 blobs:** **powdersn0w** (dora2ios-era restore exploit) — untethered restore of nearly **any iOS version the hardware can run** (up to 9.3.5 for A5), [wiki](https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/powdersn0w).
- Post-downgrade jailbreaks: any version 3.1.3→9.3.4 via Legacy-iOS-Kit's built-in chain; 9.3.5/9.3.6 via EverPwnage/iocaste; iOS 6 via Aquila ([LukeZGD/aquila](https://github.com/LukeZGD/aquila)). Anyway: pick 8.4.1 (last 32-bit-tolerant, more tweaks) or 6.1.3 (fastest) — both fine on 512 MiB.

**(a) Stay on 9.3.5 + tweaks — SOLID.**

- **EverPwnage** ([LukeZGD/EverPwnage](https://github.com/LukeZGD/EverPwnage)): iOS 7.0–9.3.6 untethered jailbreak for all 32-bit devices; supported list: A4 (iPhone 4), **A5(X): iPhone 4S; iPad 2, 3, mini 1; iPod touch 5**, A6(X): iPhone 5/5C, iPad 4; untethers: EverUntether (8.0–9.3.4), **iocaste (9.3.5/9.3.6)**, Aquila (iOS 7). Sideload via Sideloadly/PlumeImpactor or Legacy-iOS-Kit. This survives reboots — no PC needed after install — and it is **also the on-ramp for Linux**: EverPwnage's jailbroken state is what the kDFU trick needs to enter pwned DFU with no extra hardware (the owner's own repo documents exactly this chain).
- This is the state with the most working software for the device: Cydia/[Zebra](https://github.com/LukeZGD/Zebra), AppSync, emulators, SSH, old-app sideloading, iFile/NewTerm etc.

**(c) pwned DFU + custom boot images — WORKS, but see the pwned-DFU entrance problem.**

- What images exist to boot once you hold a pwned A5 (in DFU or via kDFU):
  - patched **iBSS/iBEC** regenerated from your IPSW (iBoot32Patcher-based; Legacy-iOS-Kit's pwned-iBSS mode, Cascadia's autogo-iBEC chain, checkm8_bootkit's arbitrary-iBSS boot);
  - **SSH ramdisks** (Legacy-iOS-Kit) — full Linux-based recovery shells;
  - custom **iBoot images** (custom boot logos, verbose boot);
  - **Linux**: Cascadia's A5 build (`./cascadia a5 build`, kernel 6.12 + k93ap.dts + Alpine initramfs) — the only non-iOS kernel image that exists for this hardware;
  - tethered-boot builds of **any iOS** (Legacy-iOS-Kit "Other (Tethered)"; on A5 the tether boot reboot each time needs checkm8-a5 hardware or kDFU-on-old-jailbroken-iOS).
- No NAND-resident third-party OS image exists anywhere (no "flash and go" Linux/Android/anything for k93ap).

**Ranking (honest):**
1. **Save OTA blobs 6.1.3 + 8.4.1 (+ iOS 7 blobs) immediately** — cost ≈ 10 minutes, buys insurance against Apple flipping the servers again after the July 2026 scare.
2. **EverPwnage untethered jailbreak on 9.3.5** — permanent, software-only, enables everything else incl. kDFU-based Linux RAM boots (the owner's existing `ipad-rea` plan). If you want a faster device still, downgrade to 8.4.1 or 6.1.1-6.1.3 first, then jailbreak that.
3. **Cascadia Linux 6.12 RAM boot on the iPad 2** — real, current (Nov 2026), but a research vehicle: USB shell + framebuffer console + USB networking; no touch/Wi-Fi/audio/SMP/persistence on K93 yet. Do not expect a tablet experience; expect a serial-console toy that proves the point.
4. **Tethered custom-iOS boot chains** — work, but a niche need (e.g., to dual-boot iOS 6 via DRA/powdersn0w untethered instead, which is better).
5. **"Flashing" Linux/other OSes permanently to NAND** — does not exist today. It is plausibly reachable (Cascadia's roadmap: "NAND as Linux's own storage … at the cost of iOS"), but as of 2026-11-08 it is an open work item upstream. And Android/NetBSD/FreeBSD/Windows-for-A5: **impossible with current public knowledge** — nothing to build on.

**And the host-only checkm8 quest:** drop it. Three independent sources say the A5's BootROM/USB combination requires raw-host timing no general-purpose OS stack delivers (Cascadia `boot.md`: PC-driven `gaster` gets **0-byte control transfers** on A5; Legacy-iOS-Kit wiki: "For A5(X) devices, additional hardware is required to enter pwned DFU mode"; ElcomSoft: software-only A5 support is "unfeasible or plain impossible", hence their Pico `picom8.uf2`). A Raspberry Pi Pico (RP2040, micro-USB, no Wi-Fi variant preferred) is ~$5 and has ready-made UF2 firmware ([LukeZGD Legacy-iOS-Kit-Keys `checkm8-pico.zip`](https://github.com/LukeZGD/Legacy-iOS-Kit-Keys/releases/download/a/checkm8-pico.zip), file `8940.uf2` for this iPad; instructions in the [checkm8-a5 wiki](https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/checkm8-a5)). The jailbroken-kDFU path requires no hardware at all — which makes EverPwnage the strongest single move on this board.

---

## 5. SOURCE INDEX

**The A5 Linux port (Cascadia):**
- Project Cascadia — https://github.com/rzxvx/Project-Cascadia (created 2026-08-11; pushed 2026-11-08; "Native Linux on Apple Silicons (A5 - A13)"; repo meta via GitHub API)
- Root README (devices table, K93 experiment line, background, roadmap, credits) — https://github.com/rzxvx/Project-Cascadia/blob/main/README.md
- A5 README (current status, seven problems, NAND problem, negative results, roadmap) — https://github.com/rzxvx/Project-Cascadia/blob/main/devices/a5/README.md
- K93 bring-up (the iPad 2 doc) — https://github.com/rzxvx/Project-Cascadia/blob/main/devices/a5/docs/k93-bringup.md
- A5 feasibility/boot research — https://github.com/rzxvx/Project-Cascadia/blob/main/devices/a5/docs/research/feasibility.md ; …/boot.md ; …/boot-strategy.md ; …/p105-fb.md ; …/p105-smp-bringup.md
- A5 QUICKSTART — https://github.com/rzxvx/Project-Cascadia/blob/main/devices/a5/docs/QUICKSTART.md
- DTS evidence: `devices/a5/dts/k93ap.dts`, `p105ap.dts`, `j1ap.dts`, `p102ap.dts`; patches: `drivers_irqchip`, `drivers_tty_serial_samsung_tty.c`, `phy-apple-s5l-usb` — https://github.com/rzxvx/Project-Cascadia/tree/main/devices/a5
- Third-party tracker: iPad Linux — https://ipadlinux.org/ ("Releases … Project Cascadia by rzxvx · Updated October 2026 … Not installable … iPad mini (1st gen) · Apple A5")

**Mainline gap / other Linux-on-Apple work:**
- Mainline Apple DTS starts at A7 — https://github.com/torvalds/linux/tree/master/arch/arm64/boot/dts/apple (s5l8960x* …; no 32-bit/8940 files)
- postmarketOS device catalog & generic iDevice port — https://wiki.postmarketos.org/wiki/Devices ; device stub page for this tablet: https://wiki.postmarketos.org/wiki/Apple_iPad_2_(apple-k93) ("not booting", "Pre-built images: no", "Mainline: no"; Sept-2025 revision via Wayback)
- Wikipedia: iOS-device Linux — https://en.wikipedia.org/wiki/Linux_on_Apple_devices ; OpeniBoot — https://en.wikipedia.org/wiki/OpeniBoot ; iPodLinux — https://en.wikipedia.org/wiki/IPodLinux ; checkm8 — https://en.wikipedia.org/wiki/Checkm8
- OpeniBoot repos — https://github.com/planetbeing/iphonelinux (2008-05→2023-07); https://github.com/iDroid-Project/openiBoot ; revival fork https://github.com/iProgramMC/openiBoot
- iPad Air 2 (A8X) 5.18 kernel — https://arstechnica.com/gadgets/2022/06/developers-get-linux-up-and-running-on-old-ipad-air-2-hardware/
- Hoolock Linux (A7–A11/T2) — https://github.com/HoolockLinux ; Omarchy A/Orchard (iPad 6, A10) — https://ipadlinux.org/
- U-Boot: Apple's open-source iPhone-era uboot dump — https://github.com/apple-oss-distributions/uboot ; A4-only community port — https://github.com/pmbonneau/uBoot-iPhone4 (S5L8930; last code push 2014)

**checkm8 exploitation on A5 (the central constraint):**
- axi0mX ipwndfu (checkm8; A5 listed only as "future SoC support") — https://github.com/axi0mX/ipwndfu
- checkm8-a5 (Arduino+A) — https://github.com/a1exdandy/checkm8-a5 ; stable fork + Pico — https://github.com/LukeZGD/checkm8-a5 ; wiki — https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/checkm8-a5 ; UF2s — https://github.com/LukeZGD/Legacy-iOS-Kit-Keys/releases/download/a/checkm8-pico.zip
- DSecurity checkm8 technical analysis (A5 timing quirks) — https://habr.com/en/companies/dsec/articles/472762/
- checkm8_bootkit (arbitrary iBSS on S5L8940X from pwned DFU) — https://github.com/NyanSatan/checkm8_bootkit
- iBSSloader — https://github.com/teutekeune/iBSSloader
- host-side A6-only checkm8 (for contrast) — https://github.com/LukeZGD/a6meowing
- ElcomSoft: checkm8 on iPhone 4s / iPad 2-3 / mini / ATV3, Pico-based, "software-only … unfeasible or plain impossible" — https://blog.elcomsoft.com/2022/05/checkm8-unlocking-and-imaging-the-iphone-4s/
- checkra1n supported devices ("iPhone 5s through iPhone X, iOS 12.0 and up") — https://checkra.in/ ; exploit-vs-tool distinction — https://www.bleepingcomputer.com/news/apple/checkra1n-ios-jailbreak-gets-public-beta-update-with-fixes/

**Android:**
- Project Sandcastle home + status (A10-only list) — https://projectsandcastle.org/ ; https://projectsandcastle.org/status
- Coverage: Lowyat — https://www.lowyat.net/2020/207193/project-sandcastle-run-android-on-iphone-7/ ; todoandroid guide — https://en.todoandroid.es/you-can-now-run-android-10-on-some-iphones-thanks-to-project-sandcastle/ ; HN thread — https://news.ycombinator.com/item?id=22493274

**Other OSes:**
- NetBSD evbarm/apple (M1 only, Aug 2021) — https://wiki.netbsd.org/ports/evbarm/apple/ ; ports list — https://wiki.netbsd.org/ports/
- FreeBSD-on-Apple discussion (Feb 2025) — https://groups.google.com/g/ml-freebsd-questions/c/Ayf4eMlJ0os

**Downgrade / jailbreak toolchain (current state, Nov 2026):**
- Legacy iOS Kit — https://github.com/LukeZGD/Legacy-iOS-Kit (pushed 2026-11-14) ; wiki pages: Restore-Downgrade — https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/Restore-Downgrade ; OTA-Downgrade — https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/OTA-Downgrade ; powdersn0w — https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/powdersn0w ; DRA v6 — https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/DRA-v6
- EverPwnage (7.0–9.3.6 untethered; A5 support list; iocaste) — https://github.com/LukeZGD/EverPwnage ; iocaste — https://github.com/LukeZGD/iocaste
- Vieux (OTA blobs, 32/64-bit) — https://github.com/MatthewPierson/Vieux ; Oct-2026 Windows OTA downgrader — https://github.com/LucyVR1/OTA-Downgrade-iOS-8.4.1
- July 2026 signing event + restore: 9to5Mac — https://9to5mac.com/2026/07/08/apple-stops-signing-ios-versions-for-several-older-iphones-and-ipads/ ; Mactrast — https://www.mactrast.com/2026/07/apple-just-stopped-signing-ios-and-ipados-versions-for-these-older-iphones-and-ipads/
- Community reports, Nov 2026 — https://www.reddit.com/r/LegacyJailbreak/comments/1mmfgr3/how_to_downgrade_iphone_4s_to_613_using_shsh/
- Historical A5 jailbreaks (context) — https://theapplewiki.com/wiki/Absinthe
- Hardware identification — https://www.theiphonewiki.com/wiki/K93AP ; https://www.theiphonewiki.com/wiki/K93AAP ; https://ipsw.me/iPad2,1/info

**Collected but checked, per the original questions:** "linux4apple"/Marketcircle-class efforts — no such project exists under any searchable name as of 2026-11-15 (the closest real artifact is the ipadlinux.org tracker above, which is an independent cataloguing site, not a port). David Mazières (Stanford, Secure Computer Systems) has no published A5/iDevice reverse-engineering work — no port is attributed to him anywhere in this ecosystem; the closest "Corellium-class" artifact that touches real hardware remains Project Sandcastle (A10, Android) and Cascadia (A5/A12/A13, Linux). S5L8940X "datasheets" do not circulate: the effective hardware documentation is the ADT in each IPSW plus community boardviews and GPIO/address notes accumulated in the Cascadia research folder.

---

*Report compiled 2026-11-15 from live-fetch primary sources (GitHub APIs/files, project wikis, vendor blogs, news archives, Wikipedia, Wayback Machine snapshots of the postmarketOS wiki). Every factual claim above carries the URL it was verified against at compile time. Projects' liveness statements reflect their repos' last-push dates as of 2026-11-15: Cascadia (2026-11-08, active), Legacy-iOS-Kit (2026-11-14, active), EverPwnage (2026-09-20, active), iBSSloader (2026-08-29, published snapshot), checkm8_bootkit (2025-12-21, maintained), checkm8-a5 original (2020, dormant) / LukeZGD fork (2026-04, active), Vieux (2023-02, dormant — succeeded by Legacy-iOS-Kit), OpeniBoot (abandoned 2012–2023, 2026 revival fork targets pre-A4 SoCs), iPodLinux (dead ≈2009), Sandcastle (no device-list expansion since 2020).*
