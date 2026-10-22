# Alpine rootfs for the iPad 2

Userland is **Alpine Linux (armv7)** — the same distro Cascadia boots on the
iPad mini 1. Alpine's `armv7` port matches the Cortex-A9 (ARMv7, soft-float
userland works; Cascadia builds armhf kernel + Alpine armv7 userland).

## Build

Upstream scripts do the heavy lifting (fetched by `scripts/fetch-upstreams.sh`):

```
upstream/Project-Cascadia/scripts/build-alpine-rootfs.sh   # minirootfs
upstream/Project-Cascadia/scripts/build-initramfs.sh      # initramfs cpio
```

TODO(ipad-rea): run them against our `config/k93ap.config` kernel and confirm
the initramfs boots on k93ap hardware; package list deltas (WiFi tools for
BCM4330, touch calibration tools) go here.

## Networking during bring-up

Cascadia's approach, reusable as-is:

- USB gadget `g_cdc` → CDC ECM (`usb0`, 10.55.0.2) + CDC ACM console
  (`/dev/ttyGS0`) on the same cable.
- `apk` works on-device over that link (Alpine repos reachable).
- Optional: NFS root on the host, so installed packages survive reboots
  (`./cascadia nfs` upstream).

## Later phases

- Touch: digitizer firmware from the iPad 2 IPSW; calibration via `mtcal`
  from the jailbroken iOS.
- WiFi: BCM4330 firmware + NVRAM from the iPad 2 IPSW (see
  `scripts/extract-firmware.sh`).
- Desktop: XFCE on the simplefb framebuffer with touch as pointer (upstream:
  `tools/desktop/xfce-setup.sh`).
- Persistent storage: upstream keeps iOS's NAND read-only (`ios mount`);
  NAND-as-Linux-storage is a later, optional phase (and costs iOS on Pico
  users — for us it would be a big RE project; not required for "usable").
