# Booting Linux on the iPad 2

Two things live here:

- [enter-kdfu.md](enter-kdfu.md) — how to get the jailbroken iPad 2 into
  pwned DFU **with software only** (kDFU), no Pico.
- [boot-linux.sh](boot-linux.sh) — host-side script that uploads the patched
  chain + kernel + initramfs to the iPad in kDFU/pwned DFU.

## The flow, end to end

1. iPad 2 on iOS 9.3.5, jailbroken with **EverPwnage** (untethered — survives
   reboots, so this step is done once).
2. Build the chain + kernel on the host (`scripts/`).
3. Put the iPad into **kDFU** (see enter-kdfu.md).
4. Plug into the host, run `boot/boot-linux.sh` (or Cascadia's
   `./cascadia flash --kdfu`, or Legacy-iOS-Kit's bootx path).
5. Linux boots from RAM: shell on the glass + USB console/ECM network.
6. Hold **power + home** → back to iOS. Nothing on the NAND was touched.

## Path A — ACE staging bundle (Cascadia default)

patched iBSS → autogo iBEC → staging bundle (kernel+dtb+initramfs).
Pinned to one board + iOS build (the autogo hook patches an address inside
that exact iBEC). For k93ap: pick the iOS version, find the hook address.

## Path B — Legacy-iOS-Kit `bootx`

LIK uploads a ramdisk and boots via its `bootx`. Uses LIK's saved IPSW
artifacts for iPad2,1.

Both paths are implemented upstream (iBSSloader: `scripts/run-linux-ace.sh`,
`scripts/run-linux-lik.sh`; Cascadia: `./cascadia flash`). This repo's
`boot-linux.sh` wraps them for k93ap — see the TODO markers inside.
