#!/usr/bin/env bash
#
# enter-kdfu.sh — put the jailbroken iPad 2 into kDFU over USB SSH.
#
# This is Legacy iOS Kit's `device_enter_mode kDFU` (restore.sh), made
# non-interactive and driven entirely from the host:
#
#   jailbroken iOS 9.3.5 (OpenSSH installed, device unlocked, USB plugged in)
#     -> ssh over USB (iproxy 6414 -> 22)
#     -> push kloader + pwnediBSS (= build/adt-k93ap/iBSS.k93.patched)
#     -> run kloader on the device: it loads the pwned iBSS and the iPad
#        reboots into DFU with signature checks off (05ac:1227, screen black)
#
#   ./boot/enter-kdfu.sh
#   IPAD_ROOT_PW=alpine ./boot/enter-kdfu.sh     # root pw (default: alpine)
#   IPAD_ADDR=192.168.0.x ./boot/enter-kdfu.sh  # Wi-Fi ssh instead of USB
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FW="$ROOT/build/adt-k93ap"
IBSS="$FW/iBSS.k93.patched"          # == LIK's patch_ibss output (pwnediBSS)
KLOADER="$ROOT/build/tools/kloader"

ROOT_PW="${IPAD_ROOT_PW:-alpine}"
IPAD_ADDR="${IPAD_ADDR:-}"
SSH_PORT="${IPAD_SSH_PORT:-6414}"

fail() { echo "error: $*" >&2; exit 1; }

[ -f "$IBSS" ] || fail "missing $IBSS — build it first (in the cascadia-build container):
    docker run --rm -v \"\$PWD\":/work -w /work cascadia-build bash scripts/build-chain-k93.sh"
[ -x "$KLOADER" ] || fail "missing $KLOADER — run: bash scripts/fetch-tools-k93.sh"

# device mode from the USB bus (same detection as Legacy iOS Kit on Linux)
dev_mode() {
    local pid
    pid="$(lsusb 2>/dev/null | awk '/05ac:/ {print $6}' | cut -d: -f2 | head -1)"
    case "$pid" in
        1227) echo dfu ;;
        1281) echo recovery ;;
        12*)  echo normal ;;
        *)    echo none ;;
    esac
}

mode="$(dev_mode)"
echo "==> iPad USB mode: $mode"
if [ "$mode" = recovery ]; then
    echo "==> exiting the recovery loop (irecovery -a: set auto-boot, reboot)"
    "$ROOT/build/tools/irecovery/irecovery" -a || true
    sleep 8
    mode="$(dev_mode)"
    echo "==> iPad USB mode: $mode"
fi
[ "$mode" = normal ] || fail "the iPad must be booted to iOS (normal mode), not '$mode'.
If it is showing the iTunes logo, hold power+home ~10 s until it reboots."

# --- ssh plumbing (no sshpass on this host — use an askpass helper) ---------
askpass="$(mktemp)"
iproxy_pid=""
cleanup() {
    rm -f "$askpass"
    if [ -n "$iproxy_pid" ]; then kill "$iproxy_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT
printf '#!/bin/sh\nprintf "%%s\\n" "%s"\n' "$ROOT_PW" > "$askpass"
chmod +x "$askpass"
export SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force DISPLAY=none
ssh_opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o ConnectTimeout=10 -o PubkeyAuthentication=no
          -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1)

# --- target: USB (iproxy) or Wi-Fi -----------------------------------------
if [ -n "$IPAD_ADDR" ]; then
    target="root@$IPAD_ADDR"
    port_args=()
    echo "==> target: $target (Wi-Fi)"
else
    iproxy "$SSH_PORT" 22 -s 127.0.0.1 >/dev/null 2>&1 &
    iproxy_pid=$!
    sleep 1
    target="root@127.0.0.1"
    port_args=(-p "$SSH_PORT")
    echo "==> target: $target (USB via iproxy $SSH_PORT -> 22)"
fi

# --- push kloader + pwnediBSS + run script ---------------------------------
stage="$(mktemp -d)"
cp "$KLOADER" "$stage/kloader"
cp "$IBSS"    "$stage/pwnediBSS"
printf 'chmod +x /tmp/kloader*\n/tmp/kloader /tmp/pwnediBSS\n' > "$stage/kloaders"

echo "==> ssh check"
ssh "${ssh_opts[@]}" "${port_args[@]}" "$target" true || fail "ssh to $target failed.
The iPad must be jailbroken with OpenSSH installed (Cydia -> OpenSSH), unlocked,
and connected.  If it just rebooted, a semitethered jailbreak (Phoenix / your
script) is gone — re-run the jailbreak on the iPad, then run this script again.
Wi-Fi fallback: IPAD_ADDR=<ipad ip> $0"

echo "==> pushing kloader + pwnediBSS to /tmp on the iPad"
scp -O "${ssh_opts[@]}" "${port_args[@]}" \
    "$stage/kloader" "$stage/pwnediBSS" "$stage/kloaders" "$target":/tmp/

echo "==> running kloader (the iPad reboots into DFU — screen goes black)"
ssh -t "${ssh_opts[@]}" "${port_args[@]}" "$target" "bash /tmp/kloaders" || true
# kloader reboots the device mid-command, which drops the ssh session; a
# non-zero exit here is expected and not a failure.

echo "==> waiting for kDFU (device on the bus as 05ac:1227)"
inkdfu=0
for attempt in 1 2 3 4 5; do
    if [ "$(dev_mode)" = dfu ]; then inkdfu=1; break; fi
    if [ "$attempt" -lt 5 ]; then
        echo "    not yet (attempt $attempt/5) — unplug and replug the USB cable, or press the home/power button on the iPad"
        sleep 6
    fi
done
if [ "$inkdfu" != 1 ]; then
    fail "no DFU device on the bus after 5 attempts.
kloader may have failed to run.  Force-restart the iPad (hold power+home ~10 s),
re-run the jailbreak, and run this script again."
fi
echo "==> iPad is in kDFU (DFU with the pwned iBSS).  Next: ./boot/boot-linux.sh --skip-pwn"
