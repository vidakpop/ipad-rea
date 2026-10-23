#!/usr/bin/env bash
#
# fetch-tools-k93.sh — host tools for the k93ap boot chain (no sudo needed):
#
#   build/tools/irecovery/irecovery   LukeZGD's irecovery 2.0.6 (libusb; talks to
#                                     the iPad in DFU 05ac:1227 and Recovery 05ac:1281)
#   build/tools/kloader               ramytuki's kloader (Mach-O armv7, runs ON the
#                                     jailbroken iPad; loads the pwned iBSS)
#
#   bash scripts/fetch-tools-k93.sh
#
# Both are the exact binaries Legacy iOS Kit uses for its kDFU flow
# (restore.sh `device_enter_mode kDFU`), fetched from their upstream releases so
# the boot does not depend on a Legacy-iOS-Kit checkout.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS="$ROOT/build/tools"
IREC_URL="${IREC_URL:-https://github.com/LukeZGD/irecovery/releases/download/latest/irecovery_linux-x86_64.zip}"
KLOADER_URL="${KLOADER_URL:-https://raw.githubusercontent.com/LukeZGD/Legacy-iOS-Kit/main/resources/kloader/kloader}"

fail() { echo "error: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

mkdir -p "$TOOLS/irecovery"

# --- irecovery -------------------------------------------------------------
if [ -x "$TOOLS/irecovery/irecovery" ]; then
    echo "==> irecovery already present: $TOOLS/irecovery/irecovery"
else
    have curl  || fail "curl is required"
    have unzip || fail "unzip is required"
    echo "==> downloading irecovery: $IREC_URL"
    tmp="$(mktemp -d)"
    curl -L --fail -o "$tmp/irecovery.zip" "$IREC_URL"
    unzip -o -q "$tmp/irecovery.zip" -d "$tmp/irec"
    bin="$(find "$tmp/irec" -type f -name irecovery | head -1)"
    [ -n "$bin" ] || fail "no irecovery binary inside $IREC_URL"
    install -m 0755 "$bin" "$TOOLS/irecovery/irecovery"
    rm -rf "$tmp"
    echo "==> installed $TOOLS/irecovery/irecovery"
fi
# sanity: it runs and reports its version (it exits non-zero when run with no
# args and no device, so capture the output instead of checking the exit code)
irec_out="$("$TOOLS/irecovery/irecovery" 2>&1 || true)"
echo "$irec_out" | grep -q "iRecovery - version" \
    || fail "irecovery at $TOOLS/irecovery/irecovery does not run"

# --- kloader ---------------------------------------------------------------
if [ -x "$TOOLS/kloader" ]; then
    echo "==> kloader already present: $TOOLS/kloader"
else
    have curl || fail "curl is required"
    echo "==> downloading kloader: $KLOADER_URL"
    curl -L --fail -o "$TOOLS/kloader" "$KLOADER_URL"
    chmod +x "$TOOLS/kloader"
fi
# sanity: Mach-O magic (feedface) + ARM (cputype 12) — it runs on the iPad
python3 - "$TOOLS/kloader" <<'EOF'
import struct, sys
path = sys.argv[1]
d = open(path, 'rb').read()
magic, cputype = struct.unpack('<II', d[:8])
assert magic == 0xfeedface, f"not a Mach-O: magic {magic:#x}"
assert cputype == 12, f"not ARM: cputype {cputype}"
print(f"==> kloader OK: Mach-O ARM, {len(d)} bytes")
EOF

echo "==> tools ready in $TOOLS"
