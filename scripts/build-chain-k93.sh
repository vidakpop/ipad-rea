#!/usr/bin/env bash
#
# Build the kDFU boot-chain images for the iPad 2 (iPad2,1 / k93ap / A5) from
# the stock iOS 9.3.5 (13G36) IPSW.  k93 analog of Project-Cascadia's
# scripts/build-firmware.sh.
#
#   iBSS.k93.patched                 signature patch only; stock USB receive is
#                                    left alone so the host can still upload iBEC
#   iBEC.k93.patched                 signature patch + bootargs (cs_enforcement
#                                    off, debug), no auto-go yet
#   iBEC.k93.autogo                  + auto-go hook (tools/patch-ibec-autogo-k93.py)
#   iBEC.k93.autogo.plain.dfu        the autogo iBEC repacked WITHOUT encryption
#                                    (scripts/img3pack.py).  --kdfu needs this
#                                    one: after iOS has booted the AES GID key
#                                    is gone, so a KBAG decrypts to nothing and
#                                    the pwned iBSS jumps into garbage.
#
# Runs INSIDE the cascadia-build container (see docs/ or the repo Dockerfile):
# the image carries unzip, openssl, python3+capstone, an arm-linux-gnueabihf
# cross-compiler (for the auto-go trampoline) and iBoot32Patcher built from
# source, so the result is identical on any host and needs nothing outside this
# repository and the user's own IPSW:
#
#   docker run --rm -v "$PWD":/work -w /work cascadia-build \
#       bash scripts/build-chain-k93.sh
#
# or on a host that already has unzip/openssl/python3-capstone/iBoot32Patcher/
# arm-linux-gnueabihf-gcc, run it directly.
#
# Pinned to iOS 9.3.5 / 13G36 / iPad2,1.  The auto-go hook patches a specific
# address inside this exact iBEC build (docs/k93-ibec-autogo.md), and the
# decryption keys below are that build's.  Another firmware needs both
# re-derived.
#
# The IPSW (ipsw/iPad2,1_9.3.5_13G36_Restore.ipsw, ~1.4 GB) can be deleted once
# this script has run: every blob it produces is cached under build/ (boot
# chain in build/adt-k93ap/, peripheral firmware in build/fw-k93/).  Re-running
# it just re-extracts from the IPSW; download the IPSW again from Apple if
# needed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IPSW="${IPSW:-$ROOT/ipsw/iPad2,1_9.3.5_13G36_Restore.ipsw}"
OUT="$ROOT/build/adt-k93ap"

# Public firmware keys for iPad2,1 / 13G36 (The Apple Wiki, Keys:Genoa 13G36).
# Not secret: published in the community key database, useless without the device.
IBSS_IV="7771eff1fa0c9cdf0b5e2a27c3ca4dfe"
IBSS_KEY="66fcf576384a1fd733718c795a20975d5e1ad014006556254c04ad54deff1513"
IBEC_IV="4660f2292cd8280ef853044919cea2cc"
IBEC_KEY="be7a64a7a7c60580fc4c0ee8729786412072363d2360e2970006969fc95d2b92"

BOOTARGS="${BOOTARGS:-cs_enforcement_disable=1 debug=0x14}"

# Reference hashes so a regenerated image is compared, not trusted.  The iBEC
# one is of the PLAINTEXT (before the img3 repack): the .dfu payload is AES-CBC
# downstream of this point, so a single changed byte poisons the rest and a
# .dfu comparison says nothing.  The plaintext hash is the reproducible one.
KNOWN_IBSS_MD5="0c3fce7b17b9dfc3c7b586ff6c3903a7"
KNOWN_IBEC_PLAIN_MD5="99c4b29fb15f427c152eef78ba9cb69e"

fail() { echo "error: $*" >&2; exit 1; }
md5of() { md5sum "$1" | cut -d' ' -f1; }

[ -f "$IPSW" ] || fail "no IPSW at $IPSW -- pass IPSW=/path/to/iPad2,1_9.3.5_13G36_Restore.ipsw"

# iBoot32Patcher: image default, then PATH.
PATCHER="${PATCHER:-}"
if [ -z "$PATCHER" ]; then
    if [ -x /usr/local/bin/iBoot32Patcher ]; then PATCHER=/usr/local/bin/iBoot32Patcher
    elif command -v iBoot32Patcher >/dev/null 2>&1; then PATCHER="$(command -v iBoot32Patcher)"
    else fail "no iBoot32Patcher -- run inside the cascadia-build image, or set PATCHER=/path/to/iBoot32Patcher"; fi
fi

mkdir -p "$OUT"

build_one() {
    local name="$1" iv="$2" key="$3"
    echo "==> $name: extract, decrypt, patch"
    unzip -o -j "$IPSW" "Firmware/dfu/${name}.k93.RELEASE.dfu" -d "$OUT" >/dev/null \
        || fail "$name not found in $IPSW -- is this an iPad2,1 9.3.5 IPSW?"
    python3 "$ROOT/scripts/img3decrypt-ssl.py" \
        "$OUT/${name}.k93.RELEASE.dfu" "$OUT/${name}.k93.decrypted" "$iv" "$key"
    "$PATCHER" "$OUT/${name}.k93.decrypted" "$OUT/${name}.k93.patched" -b "$BOOTARGS" >/dev/null
}

build_one iBSS "$IBSS_IV" "$IBSS_KEY"
# Signature patch only.  iBSS must keep its stock USB receive path or there is
# no way to upload iBEC over the cable.
python3 "$ROOT/scripts/verify-ibss-clean.py" "$OUT/iBSS.k93.patched"

build_one iBEC "$IBEC_IV" "$IBEC_KEY"
echo "==> iBEC: auto-go hook"
python3 "$ROOT/tools/patch-ibec-autogo-k93.py" \
    "$OUT/iBEC.k93.patched" "$OUT/iBEC.k93.autogo"
echo "==> iBEC: repack as img3 (plaintext -- the kDFU route)"
python3 "$ROOT/scripts/img3pack.py" \
    "$OUT/iBEC.k93.RELEASE.dfu" "$OUT/iBEC.k93.autogo" \
    "$OUT/iBEC.k93.autogo.plain.dfu"

echo
rc=0
for pair in "iBSS.k93.patched:$KNOWN_IBSS_MD5" "iBEC.k93.autogo:$KNOWN_IBEC_PLAIN_MD5"; do
    f=${pair%%:*}; want=${pair##*:}; got=$(md5of "$OUT/$f")
    if [ "$got" = "$want" ]; then
        echo "    ok: $f reproduces the reference byte for byte"
    else
        echo "    MISMATCH: $f is $got, expected $want"
        rc=1
    fi
done
[ "$rc" -eq 0 ] || fail "boot chain differs from the reference build"

echo
ls -l "$OUT/iBSS.k93.patched" "$OUT/iBEC.k93.patched" \
      "$OUT/iBEC.k93.autogo" "$OUT/iBEC.k93.autogo.plain.dfu"
