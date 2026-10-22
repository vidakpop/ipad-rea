#!/usr/bin/env bash
#
# extract-firmware.sh — pull device firmware out of the iPad 2's own IPSW:
#   - WiFi/BT chip firmware + NVRAM (BCM4330 on iPad 2; BCM4334 on mini 1)
#   - digitizer (touch) firmware
#   - Bluetooth patchram (if separate)
#
# Nothing Apple-owned is committed; this only produces local artifacts.
#
# Upstream reference: Project Cascadia scripts/build-firmware.sh does exactly
# this for p105ap (BCM4334 over HSIC; digitizer firmware "comes out of the
# user's IPSW with the boot chain").
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/firmware/k93ap"
IPSW="${IPSW:-$ROOT/ipsw/iPad2,1_9.3.5_13G36_Restore.ipsw}"

mkdir -p "$OUT"

[ -f "$IPSW" ] || { echo "IPSW not found: $IPSW (see scripts/extract-adt.sh)" >&2; exit 1; }

echo "== extracting firmware from $IPSW into $OUT =="
# TODO(ipad-rea): enumerate the exact .im4p payloads inside the iPad2,1 IPSW
# (WLAN/BT firmware, digitizer firmware) and the decrypt/extract steps.
# Upstream does this for p105ap — port the file list to k93ap.
# The iPad 2's WiFi is a BCM4330 (mini 1 has BCM4334): the firmware/NVRAM
# file names differ; find them in the IPSW manifest.

echo "TODO: not wired yet — see notes above." >&2
exit 2
