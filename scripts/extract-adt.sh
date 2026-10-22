#!/usr/bin/env bash
#
# extract-adt.sh — get the iPad 2's Apple Device Tree and turn it into a
# base DTS, to diff against dts/ipad2-k93ap.dts.
#
# Pipeline:
#   1. download the iPad2,1 9.3.5 (13G36) IPSW if not present
#   2. extract DeviceTree.k93ap.img3 (plus iBSS/iBEC/kernelcache for later)
#   3. decrypt the DeviceTree (AES-256-CBC, keys from The Apple Wiki)
#   4. convert ADT -> DTS with Project Cascadia's adt_to_dts.py
#   5. diff the generated base DTS against dts/ipad2-k93ap.dts
#
# Output: build/adt-k93ap/  (img3, decrypted ADT, base DTS, diff)
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UP="$ROOT/upstream"
OUT="$ROOT/build/adt-k93ap"
IPSW_DIR="$ROOT/ipsw"
IPSW="$IPSW_DIR/iPad2,1_9.3.5_13G36_Restore.ipsw"

# Direct Apple CDN (verified 200 OK, 1418211002 bytes).
IPSW_URL="${IPSW_URL:-https://appldnld.apple.com/iOS9.3.5/031-73136-20160825-6A2B0F0A-6711-11E6-BE6C-193834D2D062/iPad2,1_9.3.5_13G36_Restore.ipsw}"

# iOS 9.3.5 (13G36) iPad2,1 firmware keys.
# Source: The Apple Wiki — "Keys:Genoa 13G36 (iPad2,1)"
DT_IV="bc102fb5946554dc8925d95d4ad466aa"
DT_KEY="62ccfd18deb644e2c46d764d4222af160eb7bb40022ca573830479927a59391e"

mkdir -p "$OUT" "$IPSW_DIR"

if [ ! -f "$IPSW" ]; then
    echo "== downloading IPSW (1.36 GB) =="
    curl -L --retry 3 -o "$IPSW" "$IPSW_URL"
fi

echo "== extracting files from IPSW =="
# Member paths inside the IPSW zip (iOS 9 layout: Firmware/all_flash/... and Firmware/dfu/...)
declare -A MEMBERS=(
    ["DeviceTree.k93ap.img3"]="Firmware/all_flash/all_flash.k93ap.production/DeviceTree.k93ap.img3"
    ["iBoot.k93.RELEASE.img3"]="Firmware/all_flash/all_flash.k93ap.production/iBoot.k93.RELEASE.img3"
    ["iBEC.k93.RELEASE.dfu"]="Firmware/dfu/iBEC.k93.RELEASE.dfu"
    ["iBSS.k93.RELEASE.dfu"]="Firmware/dfu/iBSS.k93.RELEASE.dfu"
    ["kernelcache.release.k93"]="kernelcache.release.k93"
)
for out in "${!MEMBERS[@]}"; do
    unzip -p -j "$IPSW" "${MEMBERS[$out]}" > "$OUT/$out"
    echo "  extracted $out ($(stat -c%s "$OUT/$out") bytes)"
done

echo "== decrypting DeviceTree =="
python3 "$ROOT/scripts/img3decrypt-ssl.py" \
    "$OUT/DeviceTree.k93ap.img3" "$OUT/DeviceTree.k93ap.decrypted" "$DT_IV" "$DT_KEY"

echo "== ADT -> DTS =="
BASE_DTS="$OUT/ipad2-k93ap-base.dts"
if [ -f "$UP/Project-Cascadia/src/adt_to_dts.py" ]; then
    (cd "$UP/Project-Cascadia/src" && python3 adt_to_dts.py \
        "$OUT/DeviceTree.k93ap.decrypted" --full -o "$BASE_DTS")
else
    echo "Project-Cascadia not cloned — run scripts/fetch-upstreams.sh" >&2
    exit 1
fi

echo "== diff vs dts/ipad2-k93ap.dts =="
diff -u "$ROOT/dts/ipad2-k93ap.dts" "$BASE_DTS" > "$OUT/diff-vs-port.dts" || true
wc -l "$OUT/diff-vs-port.dts"
echo "review: $OUT/diff-vs-port.dts"
echo
echo "done. artifacts in $OUT"
ls -la "$OUT"
