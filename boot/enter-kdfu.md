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

## Steps (host-driven — no Cydia tweak needed)

The Legacy-iOS-Kit kDFU flow needs only **OpenSSH** on the iPad, not a tweak:

1. iPad: jailbroken (EverPwnage untethered, or your semitethered script re-run
   after every reboot), **OpenSSH installed** (Cydia → OpenSSH), unlocked,
   plugged into the host.
2. Host: `./boot/enter-kdfu.sh` — ssh over USB (iproxy 6414→22), pushes
   `kloader` + the pwned iBSS (`build/adt-k93ap/iBSS.k93.patched`), runs
   kloader on the iPad. The iPad reboots into DFU with signature checks off:
   screen black, `lsusb` shows `05ac:1227`.
   - root password default `alpine` (`IPAD_ROOT_PW=...` to override)
   - Wi-Fi instead of USB: `IPAD_ADDR=<ipad ip> ./boot/enter-kdfu.sh`
   - if kloader does not take, replug the cable or press home/power while the
     script waits (it polls 5 times)
3. Host: `./boot/boot-linux.sh --skip-pwn` uploads the boot chain.

(Alternative: a Cydia "kDFU" tweak can also trigger kDFU from on-device, but
the host-driven flow above needs no tweak and no on-device app.)

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
