#!/usr/bin/env bash
#
# boot-linux.sh — upload the k93ap Linux boot chain to an iPad 2 in
# kDFU/pwned DFU and boot it.
#
# SKELETON. The real upload mechanics live upstream (iBSSloader's
# run-linux-ace.sh / run-linux-lik.sh and Cascadia's `./cascadia flash`).
# This script wires them to the k93ap artifacts built by scripts/.
#
# Usage:
#   ./boot-linux.sh            # auto-detect device, boot with built artifacts
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPSTREAM="${UPSTREAM:-$ROOT/upstream}"

ZIMAGE="${ZIMAGE:-$UPSTREAM/Project-Cascadia/build/out/zImage}"
DTB="${DTB:-$ROOT/build/ipad2-k93ap.dtb}"
INITRD="${INITRD:-$UPSTREAM/Project-Cascadia/build/out/initramfs.cpio.gz}"

echo "== ipad-rea boot-linux.sh (k93ap) =="

for f in "$ZIMAGE" "$DTB" "$INITRD"; do
    if [ ! -f "$f" ]; then
        echo "missing artifact: $f" >&2
        echo "build first: scripts/build-kernel-k93.sh + dtc dts/ipad2-k93ap.dts" >&2
        exit 1
    fi
done

# TODO(ipad-rea): detect the iPad 2 in kDFU/pwned DFU, e.g.:
#   - `irecovery -q` and check the USB serial/state, or
#   - Legacy-iOS-Kit's device detection, or
#   - lsusb vendor/product for Apple DFU (05ac:12a8 etc.)
# Then dispatch to one of:
#   Path A (ACE staging bundle):
#     (cd "$UPSTREAM/iBSSloader" && ./scripts/run-linux-ace.sh)   # TODO: k93ap paths
#   Path B (LIK bootx):
#     (cd "$UPSTREAM/Legacy-iOS-Kit" && ./legacy-ios-kit.sh ...)  # TODO: bootx flow
#   Cascadia wrapper:
#     (cd "$UPSTREAM/Project-Cascadia" && ./cascadia flash --kdfu) # TODO: k93ap support

echo "TODO: device detection + upload dispatch not wired yet — see notes above." >&2
exit 2
