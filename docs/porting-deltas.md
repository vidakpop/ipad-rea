# Porting deltas — iPad mini 1 (p105ap) → iPad 2 (k93ap)

The SoC platform family is identical (`s5l8940x`); the work is board-level.
Everything below must be re-derived from the **k93ap ADT** (extracted from the
iPad2,1 IPSW — see `scripts/extract-adt.sh`), not guessed.

| Subsystem | p105ap (upstream) | k93ap (this port) | Action |
|---|---|---|---|
| Board config | p105ap | **k93ap** | DTS `compatible`, IPSW file names (`DeviceTree.k93ap.*`, `iBSS.k93ap.*`, `kernelcache.release.k93`) |
| SoC | S5L8942X | S5L8942 (A5 rev A) | compatible falls back to `apple,s5l8940x` — likely no driver change |
| RAM | 512 MiB @ 0x80000000 | 512 MiB @ 0x80000000 | confirm from ADT/kernel boot |
| Display | 1024x768, simplefb | 1024x768, simplefb | **no panel driver needed initially** — the patched iBEC sets up the panel and simplefb rides on it |
| Digitizer | Z2-family SPI multitouch, firmware from IPSW | similar family, own firmware | extract firmware + NVRAM from the **iPad 2** IPSW; calibration via `mtcal` from the jailbroken iOS |
| WiFi/BT | BCM4334, HSIC behind EHCI | **BCM4330** (bus TODO) | read the bus (SDIO vs HSIC) from the ADT; firmware/NVRAM from the iPad 2 IPSW; adjust kernel config (`CONFIG_BRCM*`) |
| UART | s3c6400-derivative @ 0x32500000 | base TODO from ADT | update `earlycon=` base + uart node reg |
| GPIO buttons | home/hold/vol+/vol-/side | same keys expected | re-derive gpio numbers from ADT |
| Audio | ALSA card `iPadMini` | codec TODO from ADT | likely different codec/amplifier — Phase 4+ |
| Battery gauge | bq27540 on HDQ | likely same | verify from ADT |
| Boot chain pin | iOS 8.4.1 (12H321) iBEC | **pick + document** | the autogo hook patches an address inside one specific iBEC build; choose the iOS version for k93ap (9.3.5 or 8.4.1) and find the hook address in that iBEC |
| IPSW | iPad2,5 | `iPad2,1_9.3.5_13G36` (and 8.4.1 if pinned) | `scripts/extract-adt.sh` |

## Method

1. `scripts/extract-adt.sh` → base k93ap DTS (via Cascadia/iBSSloader ADT tooling).
2. `diff` base DTS vs `dts/ipad2-k93ap.dts` (adapted from p105ap) — every
   differing node is a delta to review.
3. Update `config/k93ap.config` for the deltas (WiFi chip/bus, audio, etc.).
4. Regenerate the iBSS/iBEC chain for k93ap from the chosen IPSW.
5. Boot-test on hardware; iterate.
