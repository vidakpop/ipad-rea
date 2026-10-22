#!/usr/bin/env bash
#
# build-kernel.sh — cross-compile mainline Linux 6.12 (armv7) for the iPad 2.
#
# Strategy: reuse Project Cascadia's build system and kernel patches, but
# with OUR config fragment (config/k93ap.config) and OUR device tree
# (dts/ipad2-k93ap.dts).
#
# Prereqs: scripts/fetch-upstreams.sh, an armhf cross toolchain
#          (arm-linux-gnueabihf-), plus Cascadia's build deps (see their
#          docs/QUICKSTART.md — they build in docker).
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UP="$ROOT/upstream"
CASCADIA="$UP/Project-Cascadia"
OUT="$ROOT/build/out"
mkdir -p "$OUT"

export ARCH=arm
export CROSS_COMPILE="${CROSS_COMPILE:-arm-linux-gnueabihf-}"

[ -d "$CASCADIA" ] || { echo "run scripts/fetch-upstreams.sh first" >&2; exit 1; }

echo "== kernel source =="
# Cascadia's build-kernel.sh expects the tree at build/linux inside its own
# repo. We build in OUR build dir but reuse their patch/config pipeline:
#   1. their scripts/apply-kernel-patches.py applies patches/ onto mainline
#   2. we merge OUR config/k93ap.config on top of multi_v7_defconfig
#      (same merge their config/p105ap.config documents)
# TODO(ipad-rea): wire the exact invocation once the k93ap config is final.
# Reference (upstream, for iPad2,5):
#   (cd "$CASCADIA" && ./scripts/build-kernel.sh)
#   scripts/kconfig/merge_config.sh -m .config config/p105ap.config

echo "== device tree =="
# TODO(ipad-rea): compile dts/ipad2-k93ap.dts once the deltas are final:
#   dtc -I dts -O dtb -o "$OUT/ipad2-k93ap.dtb" "$ROOT/dts/ipad2-k93ap.dts"

echo "TODO: build not wired yet — this wrapper documents the intended flow." >&2
exit 2
