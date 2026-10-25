# checkm8 route — boot Linux on the iPad 2 with NO jailbreak

The A5 (iPad 2, CPID 0x8940, SecureROM `iBoot-838.3`) is vulnerable to
**checkm8**, the SecureROM USB exploit. It runs against the bootrom in
DFU mode, so it bypasses everything that was blocking the kDFU route:

- no jailbreak / no amfi patch needed
- no activation bypass needed (your `act.sh` "semitethered" script is an
  *activation* bypass, not a jailbreak — the device stayed stock, which is why
  every install probe kept failing with `0xe800801c`)
- no Find My iPad workaround needed (DFU mode does not care about FMI)
- no sideloading / Apple ID needed

## What happens

1. You put the iPad in **DFU mode**: hold Power+Home ~10 s until the screen
   goes black, release Power, keep holding Home until the host sees
   `Apple Mobile Device (DFU Mode)` (`05ac:1227`).
2. The bootrom is pwned. The bootrom's image-signature check is patched out
   **in memory** and the DFU serial number gains `PWND:[checkm8]`. Two ways to
   do it:
   - **Raspberry Pi Pico (RP2040) — RECOMMENDED, see
     [docs/checkm8-a5-pico.md](checkm8-a5-pico.md).** Flash
     `build/src/checkm8-a5-pico/8940.uf2` onto a Pico, boot the iPad in DFU
     off the Pico's USB host port, then move the iPad back to the Linux host.
     This is the reliable route; the A5 exploit is timing-fragile from a PC
     host.
   - `tools/checkm8-a5-pwn.py` (a self-contained Python 3 host port of the
     a1exdandy/LukeZGD A5 checkm8 sequence, talking to libusb-1.0 via ctypes)
     sends the exploit directly from the PC. Fallback/experimental — it gets
     close but the A5 drops off the bus at the reset boundary; use it for
     `--stage verify` (serial check) regardless of how the pwn was done.
3. The device is now "pwned DFU" — it looks exactly like the kDFU state the
   old chain produced (`05ac:1227`, unsigned images accepted), so the rest of
   the boot chain is unchanged:

   ```
   ./boot/boot-linux.sh --checkm8          # pwn + upload + boot, one command
   # or, if already pwned:
   ./boot/boot-linux.sh --skip-pwn
   ```

4. `irecovery` uploads `build/adt-k93ap/iBEC.k93.autogo.plain.dfu` (plaintext:
   the AES GID key is gone after an iOS boot, so KBAG images decrypt to
   nothing — same reason as over kDFU), the device re-enumerates in recovery
   (`05ac:1281`), the staging bundle is uploaded, the autogo hook fires and
   Linux boots from RAM. The NAND is untouched; Power+Home reboots into iOS.

## Notes

- The exploit is deterministic but not persistent: if the device leaves DFU
  mode (reboot), the pwn is gone — re-enter DFU and run it again.
- `tools/checkm8-a5-pwn.py --selftest` checks the extracted payload/overwrite
  hashes without needing a device.
- Payload source of truth: `build/src/checkm8-a5/` (a1exdandy) and
  `build/src/lukes-checkm8-a5/` (LukeZGD), extracted to
  `build/ipwndfu/bin/checkm8_s5l8940x*.bin` and `overwrite_s5l8940x.bin`.
  The host tool uses the classic S5L8940X payload by default; `--payload luke`
  selects the LukeZGD variant.
- Host adaptation: a PC USB stack sends DATA1 after SETUP, so the Arduino's
  0xcc "pre-packets" are toggle dummies and are not sent by the host tool.
  Stage 3 defaults to complete writes (`--write-mode complete`); use
  `--write-mode abandon --debug` for the raw Arduino-style timing.
- The old jailbreak/sideload routes (docs/k93-plusx-routes.md,
  docs/k93-no-cydia-toolbox.md) are obsolete for the Linux goal — kept for
  reference only.
