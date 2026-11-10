#!/usr/bin/env bash
# sweep.sh — ADAPTIVE checkm8 --padding sweep from the PC host.
#
# Evidence-driven search order (see docs/checkm8-route.md for the analysis):
#   * Upstream known-good paddings cluster in 0x500..0x6c0 (a1exdandy,
#     LukeZGD, axi0mX).  Untested values nearest that band go FIRST.
#   * A SURVIVOR (device alive, no PWND) means the overwrite landed in FREE
#     space — the pending io_request is adjacent, so its +-0x40 neighbours
#     jump the queue.  That is the "closest to passing" signal.
#   * A death ("no DFU device after the final reset") means the overwrite hit
#     a live structure — advance to the next value.
#   * An INVALID attempt (stage 2 did not land exactly — the tool's
#     remainder check) tested the wrong offset through no fault of the
#     padding: the SAME padding is retried, it does not count as a miss.
#   * Stage-0 wedges and wait timeouts are transient, not misses: retry the
#     same value.
#
# After the list is exhausted, the next lever is --leak (feng shui count):
#   for l in 604 608 612 616 624 628 632 636; run with each padding subset.
#
# usage: tools/sweep.sh [padding ...]     (default: research order below)
set -u
cd "$(dirname "$0")/.."
TOOL="python3 -u tools/checkm8-a5-pwn.py"
# Tested-lethal so far (kept last): 0x140* 0x580* 0x5c0 0x600 0x680 0x6c0
# 0x700 0x740 0x780*   (* = only via an invalid/botched attempt or re-run)
# Untested, nearest to the upstream-good band 0x500..0x6c0, first:
DEFAULTS="0x500 0x540 0x4c0 0x440 0x400 0x3c0 0x380 0x340 0x300 0x2c0 0x280 0x240 0x200 0x1c0 0x180 0xc0 0x80 0x40 0x580 0x5c0 0x600 0x680 0x6c0 0x700 0x740 0x780 0x140"

paddings=("$@")
[ ${#paddings[@]} -eq 0 ] && paddings=($DEFAULTS)

contains() { local x; for x in "${paddings[@]}"; do [ "$x" = "$1" ] && return 0; done; return 1; }

# insert untested +-0x40 neighbours of decimal offset $1 right after index $2
enqueue_neighbours() {
    local base=$1 idx=$2 n p
    for n in $((base + 0x40)) $((base - 0x40)); do
        (( n < 0x40 )) && continue
        (( n > 0x780 )) && continue
        p=$(printf '0x%x' "$n")
        contains "$p" || paddings=("${paddings[@]:0:$((idx+1))}" "$p" "${paddings[@]:$((idx+1))}")
    done
}

i=0
while [ $i -lt ${#paddings[@]} ]; do
    p="${paddings[$i]}"
    log="/tmp/sweep-$p.log"
    echo "================ padding=$p (attempt $((i+1))/${#paddings[@]}) ================"
    echo ">>> ENTER DFU NOW: Power+Home ~10s to black, release Power, keep holding Home"
    $TOOL --wait --wait-timeout 3600 --debug --padding "$p" 2>&1 | tee "$log"
    if grep -q 'PWND:\[checkm8\]' "$log"; then
        echo "*** SUCCESS at padding=$p — device is in pwned DFU ***"
        echo "Next: ./boot/boot-linux.sh --skip-pwn"
        exit 0
    fi
    if grep -q 'INVALID attempt' "$log"; then
        echo "--- $p: INVALID (stage 2 did not land exactly) — retrying same value, not counted ---"
        continue
    fi
    if grep -q 'no DFU device appeared within' "$log"; then
        echo "--- $p: DFU never appeared (wait timeout) — retrying same value ---"
        continue
    fi
    if grep -q 'did not (re-)enumerate' "$log"; then
        echo "--- $p: stage-0 bus reset wedged the DFU (transient) — retrying same value ---"
        continue
    fi
    if grep -q 'device did not enter pwned DFU mode' "$log"; then
        echo "--- $p SURVIVOR: overwrite landed in free space (>padding is right beside<) — neighbours queued next ---"
        enqueue_neighbours "$((p))" "$i"
    else
        echo "--- $p died (overwrite hit a live structure) — next value ---"
    fi
    i=$((i+1))
    sleep 2
done
echo "=== all paddings exhausted — next lever: sweep --leak 604..604,636 (feng shui count) ==="
exit 1
