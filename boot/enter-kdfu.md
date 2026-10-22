# Entering kDFU on the iPad 2 (software-only)

kDFU = a DFU-like mode entered **from the jailbroken OS**, giving host tools
the same unsigned-USB-upload state as checkm8 pwned DFU — without a Pi Pico.

## Prerequisites

- iPad 2 (k93ap) on **iOS 9.3.5**, jailbroken.
  - Recommended: **EverPwnage** (untethered on 9.3.5/9.3.6) — sideload the IPA
    with Sideloadly/PlumeImpactor (or Legacy-iOS-Kit on Linux), keep
    "Install Untether" enabled. Then the jailbreak — and therefore kDFU
    access — survives every reboot.
  - Phoenix (semi-untethered) also works: re-run "Kickstart Jailbreak" after
    each reboot before entering kDFU.
- USB cable + host computer (Linux or macOS; Windows via gaster/LIK tooling).

## Steps

1. With the jailbreak active, install the **kDFU** tweak from Cydia
   (TODO(ipad-rea): pin the exact package/repo — Legacy-iOS-Kit's kDFU support
   and the 3uTools "enter kDFU" guide describe the tweak + kickstart flow;
   historically: install tweak → reboot → re-jailbreak → trigger kDFU).
2. Trigger kDFU. The iPad reboots and re-enumerates on USB as a DFU device in
   the kDFU state.
3. On the host, confirm the device is seen (e.g. `irecovery -q` / `lsusb` /
   Legacy-iOS-Kit's device detection shows the kDFU/pwned state).
4. Run the boot script ([boot-linux.sh](boot-linux.sh)) or
   `./cascadia flash --kdfu` from the Cascadia tree.

## Notes

- Legacy-iOS-Kit: "The main recommendation for A5(X) devices is to just use
  **Jailbroken/kDFU mode** as much as possible."
- If kDFU entry fails: force-restart the iPad, re-jailbreak, and retry.
  (Same advice as the checkm8-a5 wiki for failed pwning.)
- Alternative without DFU at all: **kloader** (ios-kexec-utils) reboots the
  jailbroken device straight into a custom payload.

## Sources

- https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/checkm8-a5
- https://www.3u.com/tutorial/articles/4231/how-to-enter-kdfu-mode-while-downgrading-to-ios613
- https://github.com/rzxvx/Project-Cascadia/blob/main/docs/QUICKSTART.md
- https://github.com/ramytuki/ios-kexec-utils
