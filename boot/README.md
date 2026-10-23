# Booting Linux on the iPad 2

Two things live here:

- [enter-kdfu.md](enter-kdfu.md) — how to get the jailbroken iPad 2 into
  pwned DFU **with software only** (kDFU), no Pico.
- [enter-kdfu.sh](enter-kdfu.sh) — host-side script that enters kDFU over
  ssh (pushes kloader + the pwned iBSS, runs kloader on the iPad).
- [boot-linux.sh](boot-linux.sh) — host-side script that enters kDFU (via
  enter-kdfu.sh) and uploads the patched chain + kernel + staging bundle.

## The flow, end to end

1. iPad 2 on iOS 9.3.5, jailbroken with **EverPwnage** (untethered — survives
   reboots, so this step is done once), OpenSSH installed, unlocked, plugged
   into the host.
2. Build the chain + kernel on the host (`scripts/`), fetch host tools once
   (`scripts/fetch-tools-k93.sh`).
3. Run `boot/boot-linux.sh` — it enters **kDFU** itself (see enter-kdfu.md)
   and uploads the chain. `--skip-pwn` if the iPad is already in kDFU.
4. Linux boots from RAM: shell on the glass + USB console/ECM network.
5. Hold **power + home** → back to iOS. Nothing on the NAND was touched.

## Path A — ACE staging bundle (Cascadia default)

patched iBSS → autogo iBEC → staging bundle (kernel+dtb+initramfs).
Pinned to one board + iOS build (the autogo hook patches an address inside
that exact iBEC). For k93ap: pick the iOS version, find the hook address.

## Path B — Legacy-iOS-Kit `bootx`

LIK uploads a ramdisk and boots via its `bootx`. Uses LIK's saved IPSW
artifacts for iPad2,1.

Both paths are implemented upstream (iBSSloader: `scripts/run-linux-ace.sh`,
`scripts/run-linux-lik.sh`; Cascadia: `./cascadia flash`). This repo's
`boot-linux.sh` is the k93ap implementation of Path A — see
[docs/k93-boot-linux.md](../docs/k93-boot-linux.md) for the full procedure.
