# VFIO userspace xHC — the software-only checkm8 host for iBoot-838.3

## Why
The A5-838.3 exploit needs primitives no kernel-managed USB stack can emit
(measured, rounds 2-5 of docs/critical-analysis-3.md):
1. SETUP wLength=0x40 + TWO 0x40 data packets (overhang — host controllers
   enforce wLength at TD level: actual=64 observed)
2. abandon-with-no-status after full/partial data (status TD is queued
   together with data — atomic)
3. single IN packet fetch mid-sequence (no status OUT)
4. microframe-precise cancel windows

All four are just *transfer descriptor ring constructions*. A userspace xHC
driver with VFIO-mmap'd controller registers can build any TD chain the spec
allows — and more importantly can express chains usbfs never exposes.

## Hardware (this laptop, measured tonight)
- 02:00.0 Renesas uPD720202 USB 3.0 (buses 5+6, driver xhci-pci-renesas,
  IOMMU group 10 — ALONE, webcam attached). SCRIFICED to VFIO.
  - public datasheet, standard xHCI 1.0 register set
- 04:00.3 / 04:00.4 AMD Renoir USB 3.1 (buses 1-4, groups 15/16) — keep for
  system devices; iPad currently on bus 3 (04:00.3) — MOVE IT to the Renesas.
- IOMMU: AMD-Vi active (groups exist)

## Architecture
1. echo device to vfio-pci (unbind xhci-pci-renesas; the webcam's bus dies —
   harmless).
2. /dev/vfio/<group> + BAR0 mmap → xHC operational registers.
3. Init: BIOS handoff (legacy ext-cap), run/stop, DCBAA, command ring,
   event ring, primary interrupter (MSI-X or polling).
4. Port management: detect the DFU device (05ac:1227), port reset, enable
   slot, address device (slot context by hand), configure EP0 (control).
5. Xfer: build control-transfer TD chains OUR way:
   - SETUP stage TD (wLength field in SETUP contents = whatever we want)
   - data stage TDs of ARBITRARY byte counts (overhang!)
   - status TD INCLUDED OR NOT — our choice (abandon!)
   - IN data TDs (single-packet fetches)
6. Re-run the a1exdandy 838.3 sequence natively (stages already proven
   land-awaited in tools/checkm8-a5-pwn.py — port the sequence onto raw TD rings).

## Milestones
M0 controller handoff: unbind → vfio bind → mmap → read CAPLENGTH/HCSPARAMS
   → halt+reset HC → verify oper-reg writes. (validates everything)
M1 ring bring-up: command ring + event ring; issue NOP + ENABLE_SLOT; read
   port registers; port reset; observe connect.
M2 device bring-up: address the DFU device at address 1 with our own input
   contexts; read its descriptor via a hand-built control TD chain.
M3 first raw sequence: string descriptor request with a deliberately
   mismatched SETUP/wLength+data (the overhang) — observe device-side
   feedback different from usbfs (actual_count > wLength!).
M4 full 838.3 exploit on the raw driver → PWNED:[checkm8] serial.
M5 resume boot chain: iBSS/iBEC payload upload (same driver), boot-linux.sh.

## Risks
- xHC init is detail-heavy (contexts must be 64-byte aligned, flags right);
  the Renesas follows the spec closely (widely used chip; mainline driver
  source as documentation).
- If the group-10 device refuses vfio binding while webcam streams —
  unbind the uvcvideo device first.
- Loss of the webcam port is acceptable; system input stays on AMD.
- 100% software: no new hardware purchased. The controller inside this
  laptop is the "Arduino".
