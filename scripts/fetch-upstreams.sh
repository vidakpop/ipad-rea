#!/usr/bin/env bash
#
# fetch-upstreams.sh — clone the upstream projects this port builds on.
#
# Everything lands in upstream/ (gitignored). We never vendor their code into
# this repo; we keep only deltas (our DTS, our config, our wrappers).
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UP="$ROOT/upstream"
mkdir -p "$UP"

clone() { # clone <url> <dir>
    if [ -d "$UP/$2/.git" ]; then
        echo "== $2: already cloned, pulling =="
        git -C "$UP/$2" pull --ff-only -q || true
    else
        echo "== cloning $2 =="
        git clone --depth 1 -q "$1" "$UP/$2"
    fi
}

# Only Project Cascadia is needed: its sandcastle (S5L8940x) kernel patches,
# pongo loader and build scripts are the base of this port.  Legacy-iOS-Kit
# and iBSSloader are NOT part of the kDFU chain (the kDFU tweak + stock DFU
# upload replaces both), so they are not fetched — clone them by hand if a
# different entry path is ever wanted.
clone https://github.com/rzxvx/Project-Cascadia.git   Project-Cascadia

echo
echo "upstreams ready in $UP:"
ls -1 "$UP"
