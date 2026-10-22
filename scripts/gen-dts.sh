#!/usr/bin/env bash
#
# gen-dts.sh — regenerate dts/ipad2-k93ap.dts from the iPad 2's ADT.
#
# Pipeline:
#   1. parse the decrypted DeviceTree (build/adt-k93ap/DeviceTree.k93ap.decrypted)
#      into raw JSON with iBSSloader's parse_apple_dt.py
#   2. generate dts/ipad2-k93ap.dts with tools/gen_k93ap_dts.py
#   3. dump the extracted hardware facts to build/adt-k93ap/facts-k93ap.json
#
# Run scripts/extract-adt.sh first if the decrypted ADT does not exist yet.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UP="$ROOT/upstream"
OUT="$ROOT/build/adt-k93ap"
ADT="$OUT/DeviceTree.k93ap.decrypted"
JSON="$OUT/apple-k93ap-raw.json"
DTS="$ROOT/dts/ipad2-k93ap.dts"

if [ ! -f "$ADT" ]; then
    echo "missing $ADT — run scripts/extract-adt.sh first" >&2
    exit 1
fi

PARSER="$UP/iBSSloader/scripts/parse_apple_dt.py"
if [ ! -f "$PARSER" ]; then
    echo "iBSSloader not cloned — run scripts/fetch-upstreams.sh" >&2
    exit 1
fi

echo "== ADT -> raw JSON =="
python3 "$PARSER" "$ADT" -o "$JSON" --log "$OUT/parse.log"

echo "== JSON -> $DTS =="
python3 "$ROOT/tools/gen_k93ap_dts.py" "$JSON" -o "$DTS"

echo "== facts report -> $OUT/facts-k93ap.json =="
python3 "$ROOT/tools/gen_k93ap_dts.py" "$JSON" --report > "$OUT/facts-k93ap.json"

echo "done: $DTS"
