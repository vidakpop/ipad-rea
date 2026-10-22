#!/usr/bin/env bash
#
# fetch-kernel-k93.sh — put a Linux 6.12 source tree at build/linux.
#
#   bash scripts/fetch-kernel-k93.sh               # fetch it
#   KERNEL_SRC=/path/to/linux bash scripts/fetch-kernel-k93.sh   # use existing
#
# The kernel is pinned to v6.12: Project Cascadia's patches apply by anchor
# match / git apply, and a missed anchor is skipped rather than reported, so a
# tree at another version can build cleanly and boot without the patch that
# makes interrupts work.  Same pin as upstream's scripts/fetch-kernel.sh.
#
# The default source is the kernel.org release tarball, which is byte-identical
# to the v6.12 git tag but does not need github.com (unreachably slow from some
# hosts — observed at ~100 B/s while cdn.kernel.org serves ~1 MB/s).  To clone
# from git instead:
#
#   KERNEL_URL=https://github.com/torvalds/linux.git bash scripts/fetch-kernel-k93.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TREE="$ROOT/build/linux"
KERNEL_TAG="${KERNEL_TAG:-v6.12}"
KERNEL_VER="${KERNEL_TAG#v}"
TARBALL="linux-${KERNEL_VER}.tar.xz"
KERNEL_URL="${KERNEL_URL:-https://cdn.kernel.org/pub/linux/kernel/v${KERNEL_VER%%.*}.x/${TARBALL}}"

fail() { echo "error: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

check_tree() {
    [ -f "$1/Makefile" ] || return 1
    awk -F' = ' '/^VERSION/{a=$2} /^PATCHLEVEL/{b=$2} /^SUBLEVEL/{c=$2} END{print a"."b"."c}' "$1/Makefile"
}

if [ -n "${KERNEL_SRC:-}" ]; then
    [ -d "$KERNEL_SRC" ] || fail "KERNEL_SRC=$KERNEL_SRC does not exist"
    v=$(check_tree "$KERNEL_SRC") || fail "$KERNEL_SRC does not look like a kernel tree"
    echo "==> using $KERNEL_SRC (Linux $v)"
    case "$v" in
        "${KERNEL_VER}".*) : ;;
        *) echo "warning: this port is written against ${KERNEL_VER}.x, not $v." >&2 ;;
    esac
    mkdir -p "$ROOT/build"
    [ -e "$TREE" ] && [ ! -L "$TREE" ] && fail "$TREE exists and is not a symlink; move it aside first"
    ln -sfn "$KERNEL_SRC" "$TREE"
    echo "==> build/linux -> $KERNEL_SRC"
    exit 0
fi

if v=$(check_tree "$TREE" 2>/dev/null); then
    echo "==> build/linux already present (Linux $v)"
    exit 0
fi

have curl || have wget || fail "need curl or wget"
have tar || fail "tar is not installed"

echo "==> fetching $KERNEL_URL"
mkdir -p "$ROOT/build"
rm -rf "$TREE"
if [[ "$KERNEL_URL" == *.tar.* ]]; then
    tmp="$ROOT/build/$TARBALL"
    if have curl; then
        curl -fL --retry 3 -o "$tmp" "$KERNEL_URL"
    else
        wget -O "$tmp" "$KERNEL_URL"
    fi
    echo "==> extracting (one moment, ~1.3 GB of sources)"
    tar -xf "$tmp" -C "$ROOT/build"
    rm -f "$tmp"
    mv "$ROOT/build/linux-${KERNEL_VER}" "$TREE"
else
    have git || fail "git is not installed"
    git -c advice.detachedHead=false clone --depth 1 --branch "$KERNEL_TAG" "$KERNEL_URL" "$TREE"
fi

v=$(check_tree "$TREE") || fail "fetch produced something that is not a kernel tree"
case "$v" in
    "${KERNEL_VER}".*) : ;;
    *) fail "expected Linux ${KERNEL_VER}.x, got $v" ;;
esac

# apply-kernel-edits.sh drives `git -C $TREE apply` for idempotency.  git apply
# works in a plain directory too, but an (empty) repo makes the tree's state
# inspectable and costs ~10 KB.
git -C "$TREE" init -q 2>/dev/null || true

echo "==> done: Linux $v at $TREE"
