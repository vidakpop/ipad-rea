# Bypassing the A5 with software only (no Pico, no Arduino)

## The problem, precisely

checkm8 (CVE-2019-8900) is a permanent BootROM exploit for A5–A11. On A7–A11
a PC can enter pwned DFU over USB alone. **On A5/A5X/A6 it cannot**:

- ElcomSoft (2022): "the iPhone 4s uses a different USB controller requiring a
  very special approach for entering pwned DFU … For most devices susceptible
  to the checkm8 exploit experts can do with or without the Pico board.
  However, there is one notable exception, which includes the entire range of
  Apple devices based on the A5 SoC."
- Legacy-iOS-Kit wiki (checkm8-a5): "For A5(X) devices, additional hardware is
  required to enter pwned DFU mode. There are 2 methods of using checkm8-a5:
  Raspberry Pi Pico, or Arduino+USB Host Shield."

So a PC-only checkm8 pwn of the A5 BootROM is not a known-working path. The
Pico exists because the exploit needs USB timing a general-purpose host can't
provide.

## The software-only answer: you don't need to pwn the BootROM from scratch

Your iPad 2 is already jailbroken (iOS 9.3.5). From a **jailbroken** device,
two software-only routes reach the same "unsigned code over USB" state:

### Route 1 — kDFU (recommended; what Cascadia uses)

kDFU is a special DFU mode entered **from the jailbroken OS** via a Cydia
tweak. The device reboots into a DFU-like state with signature checks usable
by host tools — identical end state to checkm8 pwned DFU.

- Legacy-iOS-Kit wiki: "The main recommendation for A5(X) devices is to just
  use **Jailbroken/kDFU mode** as much as possible."
- Project Cascadia QUICKSTART: "a **jailbroken iOS 7–9.3.6** on the iPad
  itself, for `./cascadia flash --kdfu`. EverPwnage is untethered on A5, so
  this stays a one-command step. **No extra hardware at all.**"
- r/LegacyJailbreak: "Since pwndfu requires an arduino for a5 checkm8 exploit,
  the only way to restore ota/custom ipsw is by using kdfu mode."

Requirements: iPad + USB cable + computer. That's it.

### Route 2 — kloader (ios-kexec-utils)

[kloader](https://github.com/ramytuki/ios-kexec-utils) reboots a jailbroken
device **straight into a custom payload** (another OS) from userland — no DFU
step at all. Per the community: "kloader is for rebooting into pwned
DFU/another OS from a jailbroken system."

### Route 3 — fallback with hardware: checkm8-a5 + Pi Pico (~$5)

Only needed if you want pwned DFU from a **non-jailbroken** device (e.g. to
restore/downgrade without a jailbreak). Not needed for booting Linux from the
jailbreak. See [LukeZGD/checkm8-a5](https://github.com/LukeZGD/checkm8-a5) and
[ios.cfw.guide/using-checkm8-a5](https://ios.cfw.guide/using-checkm8-a5/).

## What this means for ipad-rea

The whole Linux boot is **100% software**:

```
iOS 9.3.5 + EverPwnage (untethered jailbreak)
  → kDFU (tweak, on-device)
  → host uploads patched iBSS/iBEC + Linux (USB)
  → Linux runs from RAM; power+home returns to iOS
```

Only hardware: the iPad, a USB cable, and (optionally, for early boot logs) a
3.3 V USB-TTL cable on the dock UART — see [docs/uart-console.md](docs/uart-console.md).

## Sources

- https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/checkm8-a5
- https://ios.cfw.guide/using-checkm8-a5/
- https://blog.elcomsoft.com/2022/05/checkm8-unlocking-and-imaging-the-iphone-4s/
- https://github.com/rzxvx/Project-Cascadia/blob/main/docs/QUICKSTART.md
- https://github.com/ramytuki/ios-kexec-utils
- https://www.reddit.com/r/LegacyJailbreak/wiki/guides/pwneddfu/
