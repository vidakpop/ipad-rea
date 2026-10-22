# Booting Linux on the iPad 2 (k93ap) — the full procedure

Everything below is **software only**: the iPad, a USB cable, and this host.
No Pi Pico, no Arduino (those are only needed to pwn the BootROM from a
*non*-jailbroken device — see [a5-software-only-bypass.md](a5-software-only-bypass.md)).

```
jailbroken iOS 9.3.5 (EverPwnage, untethered)
  -> kDFU            (on-device, via Legacy iOS Kit's restore.sh --kdfu)
  -> pwned iBSS      (booted by kloader from the jailbroken iOS)
  -> autogo iBEC     (uploaded by the host; PLAINTEXT image)
  -> stage1 loader   (in the staging bundle; autogo hook fires on upload EOF)
  -> Linux 6.12      (zImage + ipad2-k93ap.dtb, runs from RAM)
```

Linux runs entirely from RAM. **Nothing is written to the NAND** — power+home
reboots straight back into iOS (EverPwnage), every time.

## 1. Build everything (once, in the container)

```sh
cd "/path/to/ipad-rea"

docker run --rm -v "$PWD":/work -w /work cascadia-build \
    bash scripts/build-chain-k93.sh      # iBSS/iBEC patches + autogo hook
docker run --rm -v "$PWD":/work -w /work cascadia-build \
    bash scripts/build-kernel-k93.sh     # Linux 6.12 zImage (needs scripts/fetch-kernel-k93.sh first)
docker run --rm -v "$PWD":/work -w /work cascadia-build \
    bash scripts/build-staging-k93.sh    # dtb + stage1 loader + staging-bundle.bin
```

Artifacts you end up with:

| file | what it is |
|---|---|
| `build/adt-k93ap/iBSS.k93.patched` | signature-patched iBSS (primepwn/Pico route only) |
| `build/adt-k93ap/iBEC.k93.autogo.plain.dfu` | **the one the kDFU route uploads** — autogo hook, no KBAG |
| `build/out/staging-bundle.bin` | `[loader][pad 0x8000][zImage][dtb]`, uploaded at 0x80000000 |
| `build/out/linux-boot.bin` | stage1 loader alone (fallback upload) |

## 2. One-time host setup

Legacy iOS Kit provides `irecovery` (and the kDFU entry). Clone it and run it
once so it fetches its own tools:

```sh
git clone --depth 1 https://github.com/LukeZGD/Legacy-iOS-Kit ~/Legacy-iOS-Kit
cd ~/Legacy-iOS-Kit && ./restore.sh        # first run fetches tools; run again to reach the menu
```

The boot script finds `irecovery` on `PATH` or at `~/Legacy-iOS-Kit/bin/irecovery`.
Raw USB access needs root: the script uses `sudo` (set `SUDO=` to skip it if you
have udev rules for `05ac:12a8`).

## 3. Boot

1. iPad 2: on, jailbroken (EverPwnage boots it untethered), connected to the
   host by USB. Unlock it (passcode) if it asks.
2. Run:

   ```sh
   ./boot/boot-linux.sh
   ```

3. The script runs `~/Legacy-iOS-Kit/restore.sh --kdfu` and follows its
   prompts. The iPad **reboots into DFU**: the screen goes black and the device
   shows up as `Apple Mobile Device (DFU Mode)` (`05ac:12a8`). This is the only
   step that needs you at the device.
4. The script then uploads, in order:
   - `iBEC.k93.autogo.plain.dfu` — the pwned iBSS accepts it (signature patch);
     the iBEC comes up in Recovery mode;
   - `staging-bundle.bin` — the autogo hook fires when this upload's final USB
     transfer completes short (the bundle is deliberately not a multiple of
     `0x8000`), and the iBEC jumps to the stage1 loader at `0x80000000`.
5. The loader paints a status screen (framebuffer — may be invisible until the
   k93 FB base is confirmed; see below) and jumps to the kernel at `0x80008000`.

Useful variants:

```sh
./boot/boot-linux.sh --skip-pwn              # device already in kDFU
./boot/boot-linux.sh --no-uart               # no serial capture
UART_DEV=/dev/ttyUSB0 ./boot/boot-linux.sh   # capture the dock UART boot log
```

## 4. Watching the boot (UART)

Attach a 3.3 V USB-TTL adapter to the dock-connector UART — wiring and baud in
[uart-console.md](uart-console.md). Then:

```sh
UART_DEV=/dev/ttyUSB0 ./boot/boot-linux.sh
tail -f build/uart-linux.log
```

Expected output, in order:

```
earlycon: s3c6400_uart0 ...          <- kernel early console, 115200 8N1
... Linux 6.12.0 ... command line ...  <- the kernel proper
```

**Build 1 has no rootfs yet**: after the driver probes the kernel panics with
`Run /init as init process` / `No working init found` (root=/dev/ram0, no
initramfs embedded). That panic **is** the current milestone — it proves the
whole chain (kDFU → iBSS → autogo iBEC → loader → kernel → DTB → UART console)
works. The next task is the rootfs (Alpine armv7 initramfs, embedded into the
kernel — `INITRAMFS_DIR=build/initramfs-root` is already supported by
`scripts/build-kernel-k93.sh`).

The USB gadget (g_cdc: ACM shell + ECM network) comes up before userspace, so
once a rootfs exists the shell is reachable over USB alone:
`/dev/ttyGS0` on the device, and the ECM link on the host.

## 5. Troubleshooting

| symptom | cause |
|---|---|
| `restore.sh` says "run the script again" and exits | first run on Linux installs LIK's own dependencies; run it once standalone, then re-run `boot-linux.sh` |
| device never shows `MODE: DFU` | kloader never ran — iPad not jailbroken/unlocked, or not connected; check LIK's own output |
| iBEC uploads to 100%, then the device drops off the bus | an **encrypted** iBEC over kDFU (no GID key after iOS booted → KBAG decrypts to nothing). The script uploads `iBEC.k93.autogo.plain.dfu` by default; if you overrode `--ibec`, use the plain one |
| no `MODE: Recovery` after the iBEC upload | the iBEC did not come up — check the UART log and the screen |
| bundle uploads, nothing happens | autogo hook did not fire: the bundle must not be a multiple of `0x8000` (`build-staging-k93.sh` enforces this — check its output: `size % 0x8000 = 6110`) |
| kernel starts, no console | no UART attached and the framebuffer node is disabled (build 1) — attach UART or wait for the FB task |
| red/blue swapped on the panel (later, when FB is enabled) | pixel format: change `format` in the `framebuffer0` node from `a8r8g8b8` to `x8b8g8r8` |

## 6. Returning to iOS

Hold power+home until the Apple logo. EverPwnage boots iOS 9.3.5 as usual.
The Linux run left no trace on the NAND.

## 7. Known unverified-on-hardware items (build 1)

- **Framebuffer base**: `framebuffer0`/`fb_region` carry the p105 value
  `0x9f6fc000` as a placeholder and the node is **disabled**; the k93 base must
  be RE'd (iBEC vram init) or read from the live ADT. Until then, console is
  UART only (`console=ttySAC0`).
- **0x8000 EOF behaviour**: the autogo hook keys on a short final transfer;
  p105-proven on hardware, to be confirmed on the k93 iBEC (the bundle is padded
  off a multiple of `0x8000` either way).
- **Payload ARM-mode entry**: the hook jumps to `0x80000000` in ARM state (bit0
  clear), matching the loader's `.arm _start`.
- **SDIO reset GPIO**: the ADT sdio node's `function-device_reset` line is
  unconfirmed (Wi-Fi task).
- **BT REG_ON GPIO**: omitted from the DTS until a live ioreg dump names it;
  the `btbcm` subver-table row for the BCM43291A0 patchram name is added after
  the first boot's `dmesg` reveals the chip's LMP subversion.
- **Battery/backlight**: `apple-hdq-battery` (bq27540 on HDQ/uart5) and
  `apple-pmu-wled` are p105 drivers kept enabled — probe on k93 is unconfirmed.
- **SMP (cpu1)**: needs PMGR Core(2) + AIC IPI bring-up on k93.
