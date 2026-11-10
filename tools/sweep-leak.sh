#!/usr/bin/env bash
# sweep-leak.sh — feng-shui (--leak) sweep: sweep the heap-shaping count
# across the reference padding band, with the same retry semantics as
# sweep.sh (INVALID / stage-0 wedge / wait timeout retry the SAME combo;
# a survivor queues its neighbours).
#
# Research: the Arduino/LIK port uses exactly 620 leaks for the A5 8940.
# The Linux kernel's enumeration allocates/frees extra response buffers on
# the device heap, so the shaping count needs retuning on a PC host.  A
# +-0x10/0x20 step grid around 620 × the upstream-good padding band
# (0x6c0 = a1exdandy/LukeZGD 8940 value, 0x640 = 8942 value, 0x500 =
# t8011/t8015 value) is the smallest grid with a real chance.
#
# usage: tools/sweep-leak.sh            # default grid below
#        tools/sweep-leak.sh 604:0x6c0 636:0x6c0   # explicit leak:padding
set -u
cd "$(dirname "$0")/.."
TOOL="python3 -u tools/checkm8-a5-pwn.py"
DEFAULTS="604:0x6c0 620:0x500 616:0x6c0 628:0x6c0 636:0x6c0 588:0x6c0 604:0x640 636:0x640 604:0x500 636:0x500 620:0x540 620:0x4c0"

combos=("$@")
[ ${#combos[@]} -eq 0 ] && combos=($DEFAULTS)

contains() { local x; for x in "${combos[@]}"; do [ "$x" = "$1" ] && return 0; done; return 1; }

# queue the +-16 leak variants of $1 right after index $2 (same padding)
enqueue_leak_neighbours() {
    local leak=${1%%:*} pad=${1##*:} idx=$2 n c
    for n in $((leak + 16)) $((leak - 16)); do
        [ "$n" -le 0 ] && continue
        c="$n:$pad"
        contains "$c" || combos=("${combos[@]:0:$((idx+1))}" "$c" "${combos[@]:$((idx+1))}")
    done
}

i=0
while [ $i -lt ${#combos[@]} ]; do
    combo="${combos[$i]}"
    leak="${combo%%:*}"
    pad="${combo##*:}"
    log="/tmp/sweep-leak${leak}-${pad}.log"
    echo "======== leak=$leak padding=$pad (attempt $((i+1))/${#combos[@]}) ========"
    echo ">>> ENTER DFU NOW: Power+Home ~10s to black, release Power, keep holding Home"
    $TOOL --wait --wait-timeout 3600 --debug --leak "$leak" --padding "$pad" 2>&1 | tee "$log"
    if grep -q 'PWND:\[checkm8\]' "$log"; then
        echo "*** SUCCESS at leak=$leak padding=$pad — device is in pwned DFU ***"
        echo "Next: ./boot/boot-linux.sh --skip-pwn"
        exit 0
    fi
    if grep -q 'INVALID attempt' "$log"; then
        echo "--- $combo: INVALID (stage 2 flake) — retrying same combo, not counted ---"
        continue
    fi
    if grep -q 'no DFU device appeared within' "$log"; then
        echo "--- $combo: DFU never appeared (wait timeout) — retrying same combo ---"
        continue
    fi
    if grep -q 'did not (re-)enumerate' "$log"; then
        echo "--- $combo: stage-0 wedge (transient) — retrying same combo ---"
        continue
    fi
    if grep -q 'device did not enter pwned DFU mode' "$log"; then
        echo "--- $combo SURVIVOR: overwrite landed in free space — queueing +-16 leak neighbours ---"
        enqueue_leak_neighbours "$combo" "$i"
    else
        echo "--- $combo died — next combo ---"
    fi
    i=$((i+1))
    sleep 2
done
echo "=== leak grid exhausted ==="
exit 1
