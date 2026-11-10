#!/usr/bin/env bash
# sweep.sh — automate the checkm8 --padding sweep from the PC host.
#
# For each padding value the pwn tool waits (--wait) for the iPad to enter
# DFU by itself; the ONLY thing you do physically is the Power+Home sequence
# each time the script asks. One fresh DFU per attempt.
#
# usage:
#   tools/sweep.sh                 # full range, nearest-first (0x6c0/0x680 already failed)
#   tools/sweep.sh 0x500 0x4c0     # explicit values
#
# Logs: /tmp/sweep-<padding>.log   Success: stops and prints the next command.
set -u
cd "$(dirname "$0")/.."
TOOL="python3 -u tools/checkm8-a5-pwn.py"
# Arduino values first: 0x6c0/0x680 previously failed while the tool still
# did an extra serial-string read after stage 0 (now removed — the Arduino
# never reads strings), so they may be correct again on the PC now.
DEFAULTS="0x6c0 0x680 0x640 0x700 0x600 0x740 0x5c0 0x780 0x580 0x540 0x500 0x4c0 0x480 0x440 0x400 0x3c0 0x380 0x340 0x300 0x2c0 0x280 0x240 0x200 0x1c0 0x180 0x140 0x100 0xc0 0x80 0x40"

paddings=("$@")
[ ${#paddings[@]} -eq 0 ] && paddings=($DEFAULTS)

i=0
while [ $i -lt ${#paddings[@]} ]; do
    p="${paddings[$i]}"
    log="/tmp/sweep-$p.log"
    echo "================ padding=$p (attempt $((i+1))/${#paddings[@]}) ================"
    echo ">>> ENTER DFU NOW: Power+Home ~10s to black, release Power, keep holding Home"
    # long wait window: the tool polls sysfs continuously, so there is no
    # gap between attempts in which a DFU entry could be missed.
    $TOOL --wait --wait-timeout 3600 --debug --padding "$p" 2>&1 | tee "$log"
    if grep -q 'PWND:\[checkm8\]' "$log"; then
        echo "*** SUCCESS at padding=$p — device is in pwned DFU ***"
        echo "Next: ./boot/boot-linux.sh --skip-pwn"
        exit 0
    fi
    if grep -q 'no DFU device appeared within' "$log"; then
        echo "--- $p: DFU never appeared (wait timeout) — NOT counted, retrying same value ---"
        continue   # same index again
    fi
    echo "--- $p failed (device lost or no PWND). Hard-reset if wedged (Power+Home to Apple logo), then DFU again ---"
    i=$((i+1))
    sleep 2
done
echo "=== all paddings exhausted ==="
exit 1
