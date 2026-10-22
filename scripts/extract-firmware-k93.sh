#!/usr/bin/env bash
#
# Pull the peripheral firmware blobs out of the iPad 2's 13G36 root filesystem.
# Apple's files -- do not commit the outputs, only this script.
#
#   K93.mtprops            digitizer firmware/props (touch; ADT multi-touch,k94)
#   second.bin             BCM43291 Wi-Fi firmware (raw image, /usr/share/firmware/wifi/4329c0)
#   second.txt             the same chip's NVRAM (sromrev=3, devid=0x432e)
#   BCM43291.hcd           Bluetooth patchram, cut from /usr/sbin/BlueTool
#
# Runs on the HOST: rootfs-extract-cryptography.py needs only python3 +
# `cryptography` (no pycryptodome, no dmg/hfsplus tools, no mounting).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IPSW="${IPSW:-$ROOT/ipsw/iPad2,1_9.3.5_13G36_Restore.ipsw}"
OUT="$ROOT/build/fw-k93"
DMG="058-49123-036.dmg"
# 13G36 iPad2,1 rootfs DMG key (The Apple Wiki): AES-128 key + HMAC-SHA1 key.
KEY="f17d6a73913dfb7ca9df505d6b2a829e25797a89a9dba446d5cfef671c0b500fb201958b"

# The BT patchram module inside BlueTool.  The ADT's wifi-chipset is "43291",
# and BlueTool carries "BCM43291A0 37.4 MHz Class 1.5 Olympic Second Module"
# for it.  extract-bt-firmware.py matches MODULE as the end of that name.
BT_MODULE="${BT_MODULE:-Olympic Second Module}"

fail() { echo "error: $*" >&2; exit 1; }
[ -f "$IPSW" ] || fail "no IPSW at $IPSW"
mkdir -p "$OUT"

echo "==> touch + Wi-Fi firmware out of the root filesystem"
python3 "$ROOT/scripts/rootfs-extract-cryptography.py" "$IPSW" "$DMG" "$KEY" \
    /usr/share/firmware/multitouch/K93.mtprops            "$OUT/K93.mtprops" \
    /usr/share/firmware/wifi/4329c0/second.bin            "$OUT/second.bin" \
    /usr/share/firmware/wifi/4329c0/second.txt            "$OUT/second.txt" \
    /usr/sbin/BlueTool                                    "$OUT/BlueTool"

echo "==> Bluetooth patchram out of BlueTool ($BT_MODULE)"
python3 "$ROOT/scripts/extract-bt-firmware.py" "$OUT/BlueTool" "$BT_MODULE" "$OUT/BCM43291.hcd"
rm -f "$OUT/BlueTool"

echo
echo "==> verify against the reference hashes"
rc=0
check() { # file want_sha256
    local got
    got=$(sha256sum "$1" | cut -d' ' -f1)
    if [ "$got" = "$2" ]; then echo "    ok: $1"; else
        echo "    MISMATCH: $1 is $got, expected $2"; rc=1; fi
}
check "$OUT/K93.mtprops"   71bf5e8266db64f83ae61d1e97d200604937f54ea72941b8ffdb54c124081190
check "$OUT/second.bin"    be184cd0f014b3f2c5a1f225f780d5abfb2e4777a77516b1507b21764f63f9a7
check "$OUT/second.txt"    d6470e0f74d38c25de797139cdaa2d85645ed7381dbbb0d0a48d031da37a8306
check "$OUT/BCM43291.hcd"  92719ab538313a07aa76ebdd7c11ddef25bc22ee7b4de0567ab0c6697680d4e4
[ "$rc" -eq 0 ] || fail "firmware blobs differ from the reference extraction"

ls -l "$OUT"
