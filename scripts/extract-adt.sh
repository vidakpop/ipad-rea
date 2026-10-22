#!/usr/bin/env bash
#
# extract-adt.sh — get the iPad 2's Apple Device Tree and turn it into a
# base DTS, to diff against dts/ipad2-k93ap.dts.
#
# The ADT is the hardware description (MMIO addresses, GPIO map, buses).
# It ships inside the IPSW as DeviceTree.k93ap.*.im4p.
#
# Steps:
#   1. download the iPad2,1 IPSW (or point IPSW at a local file)
#   2. unzip, locate DeviceTree.k93ap.*.im4p
#   3. decrypt it (keys are public on The iPhone Wiki — Durango 8L1 (iPad2,1))
#   4. convert ADT -> DTS with the upstream tooling
#      (iBSSloader: `make dts` does ADT -> JSON -> DTS -> DTB;
#       Cascadia: src/adt_to_dts.py)
#
# Output: build/adt-k93ap/ (raw ADT, JSON, base DTS)
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UP="$ROOT/upstream"
OUT="$ROOT/build/adt-k93ap"

# iPad2,1, iOS 9.3.5 (13G36). Override with IPSW=/path/to.ipsw or IPSW_URL=...
IPSW_URL="${IPSW_URL:-https://ipsw.me/iPad2,1}"   # TODO: pin exact Apple CDN URL for 9.3.5
IPSW="${IPSW:-$ROOT/ipsw/iPad2,1_9.3.5_13G36_Restore.ipsw}"

mkdir -p "$OUT" "$ROOT/ipsw"

if [ ! -f "$IPSW" ]; then
    echo "== downloading IPSW =="
    echo "TODO: resolve the direct Apple CDN URL for iPad2,1 9.3.5 13G36 from $IPSW_URL"
    echo "      then: curl -L -o \"$IPSW\" <url>"
    exit 2
fi

echo "== extracting DeviceTree from $IPSW =="
TMP="$(mktemp -d)"
(cd "$TMP" && unzip -q -o "$IPSW" '*/DeviceTree.k93ap*' 'DeviceTree.k93ap*' 2>/dev/null || \
    unzip -q -l "$IPSW" | grep -i devicetree)
DT_IM4P="$(find "$TMP" -iname 'DeviceTree.k93ap*.im4p' | head -1)"
if [ -z "$DT_IM4P" ]; then
    echo "DeviceTree.k93ap im4p not found in IPSW" >&2
    exit 1
fi
cp "$DT_IM4P" "$OUT/"

echo "== decrypting (TODO: wire in the exact decrypt step) =="
echo "keys for DeviceTree.k93ap.* are on The iPhone Wiki:"
echo "  https://www.theiphonewiki.com/wiki/Durango_8L1_(iPad2,1)"
echo "upstream decrypt/patch flow: iBSSloader scripts/build-ibec.sh (needs IPSW),"
echo "Cascadia ./cascadia firmware (regenerates the chain from a stock IPSW)."

echo "== converting ADT -> DTS =="
if [ -f "$UP/iBSSloader/Makefile" ]; then
    echo "hint: (cd $UP/iBSSloader && make dts)   # ADT -> JSON -> DTS -> DTB"
fi
if [ -f "$UP/Project-Cascadia/src/adt_to_dts.py" ]; then
    echo "hint: python3 $UP/Project-Cascadia/src/adt_to_dts.py <adt.bin> > $OUT/ipad2-k93ap-base.dts"
fi

echo
echo "done (partial). artifacts in $OUT"
