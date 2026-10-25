# checkm8 route — boot Linux on the iPad 2 with NO jailbreak

The A5 (iPad 2, CPID 0x8947, SecureROM `iBoot-1458.2`) is vulnerable to
**checkm8**, axi0mX's SecureROM USB exploit. It runs against the bootrom in
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
2. `tools/checkm8-pwn.py` (a self-contained Python 3 port of the A5 path of
   `build/ipwndfu/checkm8.py`, talking to libusb-1.0 via ctypes) sends the
   exploit. The bootrom's image-signature check is patched out **in memory**
   and the DFU serial number gains `PWND:[checkm8]`.
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
- `tools/checkm8-pwn.py --selftest` builds the payload and prints its hashes
  without needing a device.
- Payload source of truth: `build/ipwndfu/` (axi0mX's ipwndfu, cloned).
  The A5 constants/payload construction in `tools/checkm8-pwn.py` mirror
  `payload(0x8947)` in `build/ipwndfu/checkm8.py` exactly.
- The old jailbreak/sideload routes (docs/k93-plusx-routes.md,
  docs/k93-no-cydia-toolbox.md) are obsolete for the Linux goal — kept for
  reference only.
