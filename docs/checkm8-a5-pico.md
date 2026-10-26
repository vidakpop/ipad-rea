# checkm8 on A5 via Raspberry Pi Pico (RP2040) — the reliable route

The PC-host port of the A5 checkm8 sequence (`tools/checkm8-a5-pwn.py`) is
timing-fragile at the A5 heap/reset boundary: the exploit needs exact USB
data-toggle and transfer-cancel timing, and a PC host's USB stack shifts it
(the Arduino original was written for a MAX3421E host controller that sends
DATA0 where a PC sends DATA1, and a PC submits complete control transfers
where the exploit needs abandoned ones). The documented, reliable way to
pwn an A5 SecureROM DFU is a **Raspberry Pi Pico (RP2040)** running the
checkm8-a5 firmware as a USB host.

This matters for the iPad 2 (iPad2,1 / k93ap, CPID `0x8940`, SecureROM
`iBoot-838.3`): once the bootrom is pwned, the rest of the chain is exactly
the same as kDFU (`boot/boot-linux.sh --skip-pwn`).

## Hardware needed

- 1x **Raspberry Pi Pico** (RP2040). **NOT** a Pico 2 / Pico 2 W (RP2350) —
  the Legacy-iOS-Kit wiki warns the firmware does not work on RP2350.
- 1x USB cable for the Pico (micro-USB), 1x USB cable for the iPad (30-pin or
  Lightning depending on the iPad — iPad 2 uses 30-pin).
- The Pico acts as a **USB host**: it powers and talks to the iPad directly.
  A powered USB hub between the Pico and the iPad is fine; a direct cable is
  preferred (the original notes warn against hubs/DCSD-style cables for the
  exploit itself).

## Firmware files (already in this repo, gitignored research clone)

```
build/src/checkm8-a5-pico/
├── 8940.uf2     <- iPad 2 / iPhone 4S / iPad 3 (A5, S5L8940)  USE THIS ONE
├── 8942.uf2     <- A5X (S5L8942)
└── 8945.uf2     <- A5 (S5L8945, later A5 variants)
```

Source: `prosch88/checkm8-a5-pico` (files archived from a Reddit post; the
walkthrough is ElcomSoft's "checkm8: unlocking and imaging the iPhone 4S"
blog post). Our iPad 2 is CPID `0x8940`, so flash **`8940.uf2`**.

## Procedure

### 1. Flash the Pico

1. Hold the Pico's **BOOTSEL** button and plug it into the PC (micro-USB).
2. It appears as a mass-storage volume (`RPI-RP2`).
3. Copy `build/src/checkm8-a5-pico/8940.uf2` onto that volume.
4. The Pico reboots by itself and runs the checkm8-a5 USB-host firmware.
   (There is no serial console output you need to watch; the onboard LED
   blinks while it waits for / works on a device.)
5. Unplug the Pico from the PC.

### 2. Pwn the iPad

1. Put the iPad 2 in **DFU mode**: hold Power+Home ~10 s until the screen
   goes black, release Power, keep holding Home until the host sees
   `Apple Mobile Device (DFU Mode)` (`05ac:1227`).
2. Plug the iPad into the **powered Pico** (USB host side). Do not plug the
   iPad into the PC.
3. Wait. The Pico runs the checkm8 sequence by itself. On success the DFU
   serial number of the iPad gains `PWND:[checkm8]`.
4. Unplug the iPad from the Pico and plug it into the **Linux host**.

### 3. Verify the pwn from the Linux host

`lsusb` alone is not enough — read the serial number:

```
python3 tools/checkm8-a5-pwn.py --stage verify
# or, any libusb tool that prints the DFU serial; it must contain:
#   PWND:[checkm8]
# full expected serial:
#   CPID:8940 CPRV:21 CPFM:03 SCEP:01 BDID:04 ECID:... IBFL:00 SRTG:[iBoot-838.3] PWND:[checkm8]
```

If the serial does not contain `PWND:[checkm8]`, the exploit did not land:
hard-reset the iPad (Power+Home until the Apple logo), re-enter DFU, and try
again with a direct cable.

### 4. Boot Linux

The device is now in pwned DFU — the same state kDFU produced:

```
./boot/boot-linux.sh --skip-pwn
```

Expected chain: iBEC upload (`build/adt-k93ap/iBEC.k93.autogo.plain.dfu`)
→ device re-enumerates in recovery (`05ac:1281`) → staging bundle upload →
autogo hook → Linux boots from RAM. Success milestone: kernel panic after
`Run /init as init process` (no rootfs yet). The NAND is untouched;
Power+Home reboots into iOS.

**Do not reboot the iPad while it is pwned unless you are ready to redo
steps 2–3** — the pwn lives only in the bootrom's RAM.

## Why not just keep retrying the PC-host tool?

`tools/checkm8-a5-pwn.py` implements the same sequence with raw libusb
control transfers (cancelled URBs for the heap feng shui, an incomplete
DNLOAD cancelled before its final packet, no 0xcc pre-packets because a PC
host already sends DATA1). It gets close — stage 2 completes — but the
A5 drops off the bus at the reset boundary more often than not. Every
failed attempt wedges the DFU and costs a hard reset + DFU re-entry. The
Pico firmware runs the timing on a microcontroller with a USB host stack
that matches what the exploit was written for, and is the route the
community settled on for A5. Use the PC tool for `--stage verify` and as a
fallback experiment; use the Pico for the actual pwn.

## Fallback: PC-host attempt (one shot per fresh DFU)

If no Pico is available:

1. Hard-reset the iPad (Power+Home until the Apple logo), then DFU:
   Power+Home ~10 s until black, release Power, keep holding Home.
2. Do **not** probe the device first (any control transfer can wedge it).
3. Start the tool first, then put the iPad in DFU — `--wait` polls sysfs
   (zero USB traffic) and fires the instant the device appears:

   ```
   python3 -u tools/checkm8-a5-pwn.py --wait --debug
   ```

4. Success indicators in the debug output:
   - stage 1 feng-shui requests: `status=CANCELLED` (or `STALL`)
   - stage 2: `incomplete DNLOAD status=CANCELLED actual=<0x700` (a log
     line `... (N full packets), 0x... remainder to send` follows, then the
     `remainder OUT` transfer).  `actual=1792`/`0x700` aborts the run — that
     means the device fired end_of_transfer and the exploit is dead
   - stage 3: critical IN `status=CANCELLED` or `STALL` (not `COMPLETED`)
   - final serial contains `PWND:[checkm8]`
5. Tunables (only with a fresh DFU between attempts): `--leak 620|626`,
   `--leak-delay-ms`, `--feng-shui-mode in-cancel|setup-only`,
   `--init-resets 0|1|3`, `--spin-us` (setup-stage cancel deadline for the
   critical IN), `--out-spin-us` (stage-2 DNLOAD cancel deadline; lower it
   if the DNLOAD ever reports `actual=0x700`), `--payload classic|luke`.
   The kernel's enumeration traffic (string reads etc.) shifts the heap
   relative to the Arduino, so `--leak` is the most likely knob.
