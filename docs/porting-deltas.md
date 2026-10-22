# Porting deltas — iPad mini 1 (p105ap) → iPad 2 (k93ap)

The SoC platform family is identical (`s5l8940x`); the work is board-level.
Every value below marked **CONFIRMED** was read out of the k93ap ADT
extracted from the iPad2,1 9.3.5 (13G36) IPSW by `scripts/extract-adt.sh` /
`scripts/gen-dts.sh` — not guessed. `dts/ipad2-k93ap.dts` is fully generated
from that ADT (`tools/gen_k93ap_dts.py`).

| Subsystem | p105ap (upstream) | k93ap (this port) | Status |
|---|---|---|---|
| Board config | p105ap | **k93ap** | CONFIRMED |
| SoC | S5L8942X | S5L8942 (A5 rev A) | CONFIRMED — compatible falls back to `apple,s5l8940x`, no driver change |
| RAM | 512 MiB @ 0x80000000 | 512 MiB @ 0x80000000 | CONFIRMED (DTS: `reg = <0x80000000 0x1f6fc000>`; static ADT `/memory` is zeroed, iBoot fills it) |
| Display | 768x1024 portrait simplefb, stride 3072, a8r8g8b8 | identical | CONFIRMED — same scanout geometry; FB base still patched at boot (see Open items) |
| UART console | 0x32500000, AIC irq **22** | 0x32500000, AIC irq **21** | CONFIRMED — only IRQ differs; `earlycon=s3c6400,0x32500000` unchanged |
| GPIO buttons | home=0 hold=1 volup=2 voldown=3 side=4 | home=0 hold=1 volup=**57** voldown=**59** side=**50** | CONFIRMED from ADT `/device-tree/buttons` (hall sensor skipped) |
| Digitizer | Z2 multitouch on SPI1 | `multi-touch,k94` on SPI1 @ 0x32100000, irq gpio 21, 5 MHz | CONFIRMED wiring; firmware/NVRAM still to extract from iPad 2 IPSW |
| WiFi | BCM4334, HSIC behind EHCI | **BCM4330 on SDIO** — `sdio,s5l8940x` @ arm-io 0x0 (phys 0x30000000), irq 39, 4-bit @ 51.3 MHz, `wlan.*`/`bcom.*` props on the node | CONFIRMED bus (biggest delta). Needs a new s5l8940x SDIO host driver + brcmfmac; firmware from IPSW |
| Bluetooth | on uart1 @ 1.5 Mbaud | `bluetooth,n88` on **uart3** @ 0x32800000, 3 Mbaud | CONFIRMED from ADT |
| USB | EHCI/OHCI host (WiFi) + gadget | dock-connector EHCI @ 0x36400000 + OHCI0/1 @ 0x36500000/0x36600000 (irqs 12/13/14); `usb-device` child = the iPad itself (g_cdc gadget) | CONFIRMED — no WiFi on USB here |
| Audio | see upstream `docs/research/p105-audio.md` (MCA0/I2S1) | `audio-control,cs42l63` on i2c0 @ 0x4a, `audio-data,cs42l63` on i2s0, headset switch `ts3a8235` @ 0x3b, spkr_mute gpio | CONFIRMED codec — Phase 4+ |
| Battery gauge | bq27540 on HDQ | `gas-gauge,bq27540` on **uart5** @ 0x32a00000 | CONFIRMED — same chip, different UART |
| PMU | d1946 on i2c | `pmu,d1946` on i2c0 @ 0x3c | CONFIRMED — same PMIC |
| Sensors | — | i2c1: compass `akm8975b` @ 0xe, prox `ad7147a` @ 0x2c; i2c2: accel `lis331dlh` @ 0x19, gyro `ap3gdl` @ 0x68, ALS `tsl2581` @ 0x39 | CONFIRMED from ADT (out of scope initially) |
| AIC | 0x3f200000 | 0x3f200000, `#main-cpus = <2>` | CONFIRMED — identical |
| PMU timer | hwirq 135 | hwirq 135 | CONFIRMED — identical |
| Boot chain pin | iOS 8.4.1 (12H321) iBEC | **iOS 9.3.5 (13G36) iBEC chosen** | OPEN — autogo hook address still to find in the k93 9.3.5 iBEC (`find_autogo_hook.py`) |
| IPSW | iPad2,5 | `iPad2,1_9.3.5_13G36_Restore.ipsw` | CONFIRMED — `scripts/extract-adt.sh` |

## Open items (not yet confirmed)

- **Framebuffer base**: the static ADT `/vram` (and `/chosen/memory-map`) are
  zeroed — iBoot assigns the base at runtime. Read it from the k93 iBEC with
  iBSSloader's `scripts/analyze-ibec-display.py`, or from the live ADT via
  pongoOS/ioreg on the running iPad. DTS currently patches `0x9f6fc000`
  (top of the 512 MiB) as a placeholder.
- **WiFi reset gpio**: present only as an Apple `function-device_reset`
  descriptor on the sdio node; the encoding is not a plain gpio number.
  Confirm from a live `ioreg` dump on the jailbroken iPad.
- **Touch firmware + NVRAM**: extract from the iPad 2 IPSW rootfs DMG
  (`058-49123-036.dmg`) — not yet done.
- **BCM4330 WiFi firmware/NVRAM**: same rootfs DMG.
- **SDIO host driver**: no upstream driver binds `sdio,s5l8940x` — new work.

## Method (as executed)

1. `scripts/extract-adt.sh` → downloads IPSW, extracts + decrypts
   DeviceTree.k93ap, converts with Cascadia `adt_to_dts.py`, diffs against
   `dts/ipad2-k93ap.dts` → `build/adt-k93ap/diff-vs-port.dts`.
2. `scripts/gen-dts.sh` → `parse_apple_dt.py` (93 nodes, 1247 props, 0 errors)
   → `apple-k93ap-raw.json` → `tools/gen_k93ap_dts.py` → `dts/ipad2-k93ap.dts`
   + `build/adt-k93ap/facts-k93ap.json`.
3. Cross-check: running the **unmodified** p105 generator on the k93 JSON
   yields a DTS identical to upstream `p105ap.dts` except the UART irq —
   confirming the core SoC addresses are shared between the boards.
4. Update `config/k93ap.config` for the deltas (SDIO WiFi instead of USB,
   CS42L63 audio path, etc.).
5. Boot-test on hardware; iterate.
