#!/usr/bin/env bash
#
# enter-kdfu-nossy.sh — put the iPad 2 (iOS 9.3.5, k93ap) into kDFU with no
# ssh, no Cydia and no OpenSSH: the whole chain runs from the host over USB.
#
#   jailbroken iPad (your semitethered script), unlocked, plugged in
#     -> probe the jailbreak (unsigned app install must not fail at signature)
#     -> stage kloader + the pwned iBSS under /var/mobile/Media/kdfu/
#     -> launch kloader as root via com.apple.debugserver
#        (kloader loads the pwned iBSS; the device reboots into DFU: the
#         screen goes black and lsusb shows 05ac:1227)
#     -> poll the USB bus for 05ac:1227
#
# kloader must be executable (+x) somewhere debugserver can see it.  Two
# candidates are tried, in order:
#   1. /Developer/usr/bin/kloader — present when the mounted Developer Disk
#      Image is the "kdfu" variant (build/ddi/kdfu-ddi.dmg, mounted with
#      tools/ddi-swap.py); the image carries it at mode 0755.
#   2. /var/mobile/Media/kdfu/kloader — needs mode 0755, e.g. restored from a
#      patched backup (tools/mbdb-add.py + idevicebackup2 restore; requires
#      Find My iPad to be off) or chmod'ed over ssh if the jailbreak left sshd.
#
# After kDFU: ./boot/boot-linux.sh --skip-pwn boots Linux from RAM.
#
# Usage: ./boot/enter-kdfu-nossy.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UDID="${UDID:-ae85db46b1dd7faa563fc6eb53780515a67dfcc7}"
PY3="${PY3:-$ROOT/build/p3venv/bin/python}"
STAGE="$ROOT/build/tools"

echo "== ipad-rea: enter kDFU (no ssh, no Cydia) =="

# ---------------------------------------------------------------- jailbreak --
echo "==> jailbreak probe: unsigned app install (build/fakeapp/Kdfu.app)"
probe="$("$PY3" "$ROOT/tools/zipconduit-install.py" "$ROOT/build/fakeapp/Kdfu.app" 2>&1 || true)"
if echo "$probe" | grep -q "0xe800801c"; then
    echo "    the iPad looks STOCK — the install was rejected at signature" >&2
    echo "    verification.  Run your semitethered jailbreak script first," >&2
    echo "    keep the iPad unlocked and plugged in, then re-run this script." >&2
    exit 1
fi
echo "    not rejected at signature verification -> jailbreak active"

# ------------------------------------------------------------------ staging --
echo "==> staging kloader + pwnediBSS into /var/mobile/Media/kdfu/"
"$PY3" "$ROOT/tools/zipconduit-push.py" kdfu "$STAGE/kloader" "$STAGE/pwnediBSS" | tail -1

# ------------------------------------------------------------------- launch --
# launch <kloader-on-device> <pwnediBSS-on-device>: 0 if debugserver accepted
# the launch (which on a jailbroken device means kloader is running as root).
launch() {
    local out
    out="$(python3 "$ROOT/tools/debugserver-launch.py" "$1" "$2" 2>&1 || true)"
    echo "$out" | grep "qLaunchSuccess" | sed 's/^/    /'
    echo "$out" | grep -q "resp='OK'"
}

try() {
    echo "==> trying $1"
    if launch "$1" "$2"; then
        echo "    launched as root -> the device is rebooting into kDFU"
        return 0
    fi
    echo "    not launchable here (missing, or not +x)"
    return 1
}

ok=0
if try /Developer/usr/bin/kloader /Developer/usr/bin/pwnediBSS; then ok=1; fi
if [ "$ok" = 0 ]; then
    if try /var/mobile/Media/kdfu/kloader /var/mobile/Media/kdfu/pwnediBSS; then ok=1; fi
fi
if [ "$ok" = 0 ]; then
    echo
    echo "error: no executable kloader found for debugserver to launch." >&2
    echo "  Need one of:" >&2
    echo "   - the kdfu Developer Disk Image mounted (tools/ddi-swap.py" >&2
    echo "     build/ddi/kdfu-ddi.dmg ...), which carries kloader at 0755, or" >&2
    echo "   - /var/mobile/Media/kdfu/kloader at mode 0755 (patched-backup" >&2
    echo "     restore: tools/mbdb-add.py + idevicebackup2 restore, or ssh" >&2
    echo "     chmod if the jailbreak left sshd)." >&2
    exit 1
fi

# --------------------------------------------------------------------- kDFU --
echo "==> waiting for the device to enumerate as DFU (05ac:1227)"
indfu=0
for _ in $(seq 1 30); do
    sleep 1
    if lsusb 2>/dev/null | grep -q "05ac:1227"; then indfu=1; break; fi
done
if [ "$indfu" = 1 ]; then
    echo "==> kDFU reached (05ac:1227).  Next: ./boot/boot-linux.sh --skip-pwn"
else
    echo "    the device did not enter DFU (bus: $(lsusb 2>/dev/null | grep 05ac || echo none))" >&2
    echo "    check the iPad screen and the syslog (idevicesyslog)" >&2
    exit 1
fi
