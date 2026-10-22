# k93 peripheral firmware blobs (from the 13G36 root filesystem)

Extracted from the iPad 2's iOS 9.3.5 root filesystem (`058-49123-036.dmg`)
with `scripts/extract-firmware-k93.sh` (host-runnable; needs only python3 +
`cryptography`). These are Apple's files — the blobs are **not** committed,
only the scripts and this doc.

## Chips (from the ADT)

| peripheral | ADT compatible / prop | chip |
|---|---|---|
| touch | `multi-touch,k94` | Broadcom digitizer, mtprops `K93.mtprops` |
| Wi-Fi | `sdio,s5l8940x` host; `wifi-chipset` = `43291` | Broadcom BCM43291 on SDIO, 4-bit @ 51.3 MHz, AIC irq 39 |
| Bluetooth | `bluetooth,n88` (uart3) | Broadcom BCM43291A0 (combo with Wi-Fi) |

The Wi-Fi NVRAM confirms it: `vendid=0x14e4` (Broadcom), `devid=0x432e`,
`sromrev=3`, and the firmware directory is `wifi/4329c0/`.

## Extracted blobs

| output | rootfs path | bytes | sha256 |
|---|---|---|---|
| `K93.mtprops` | `/usr/share/firmware/multitouch/K93.mtprops` | 70355 | `71bf5e82…081190` |
| `second.bin` | `/usr/share/firmware/wifi/4329c0/second.bin` | 282847 | `be184cd0…f63f9a7` |
| `second.txt` | `/usr/share/firmware/wifi/4329c0/second.txt` | 890 | `d6470e0f…37a8306` |
| `BCM43291.hcd` | cut from `/usr/sbin/BlueTool` | 17062 | `92719ab5…80d4e4` |

(Full hashes are pinned in `scripts/extract-firmware-k93.sh`.)

* `K93.mtprops` — XML plist, the digitizer's firmware/calibration. The
  `multi-touch,k94` driver loads it; needed for touch.
* `second.txt` — the Wi-Fi NVRAM (59 `key=value` lines: `sromrev`, `pa0b0`…,
  `xtalfreq=37400`, …). Goes inside the TRX (see below).
* `second.bin` — the Wi-Fi firmware **raw image**. It is *not* a Broadcom TRX
  (no `HDR0` magic); it starts `00 00 00 00 7d 0a 00 00 …`. To load it with
  upstream `brcmfmac` it must be wrapped in a TRX container (magic `HDR0`,
  length, CRC32, version 1, one section = this image) and then have the NVRAM
  appended (`scripts/trx-add-nvram.py`, same as the p105 port's
  `borg.trx` + `borg-t-st.txt` → `brcmfmac4334.bin`). That wrap is Wi-Fi-driver
  work, not extraction; flagged here so the format is not mistaken for a TRX.
* `BCM43291.hcd` — Bluetooth patchram (HCD: Write_RAM `0xfc4c` commands +
  Launch_RAM `0xfc4e`), selected by module name `Olympic Second Module` from
  BlueTool's "BCM43291A0 37.4 MHz Class 1.5 Olympic Second Module" (4 identical
  copies, sha256 `92719ab5…`). `btbcm` loads it as `brcm/BCM43291.hcd`.

## Reproduce

```
bash scripts/extract-firmware-k93.sh        # writes build/fw-k93/, verifies hashes
```

`scripts/rootfs-list-k93.py IPSW DMG KEY DIR…` lists a directory inside the
rootfs (used to find the `multitouch/K93.mtprops` and `wifi/4329c0/` paths).
