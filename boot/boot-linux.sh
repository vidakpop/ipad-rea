#!/usr/bin/env bash
#
# boot-linux.sh — boot Linux on the iPad 2 over USB (kDFU route, no hardware).
#
#   ./boot/boot-linux.sh              # enter kDFU over ssh, then upload the chain
#   ./boot/boot-linux.sh --skip-pwn   # the device is already in kDFU (DFU on the bus)
#   ./boot/boot-linux.sh --kdfu-lik   # enter kDFU with Legacy iOS Kit's interactive restore.sh
#   ./boot/boot-linux.sh --no-uart    # skip the serial capture
#   UART_DEV=/dev/ttyUSB0 ./boot/boot-linux.sh   # capture the dock UART log too
#
# Chain (docs/k93-boot-linux.md has the full procedure):
#
#   jailbroken iOS 9.3.5 (OpenSSH installed, unlocked, USB)
#     -> boot/enter-kdfu.sh: ssh + kloader boots the pwned iBSS
#        (the device reboots into DFU, screen goes black, 05ac:1227)
#     -> irecovery -f iBEC.k93.autogo.plain.dfu   (PLAINTEXT: over kDFU the AES
#                                                   GID key is gone, a KBAG
#                                                   image decrypts to nothing)
#     -> irecovery -f staging-bundle.bin          (the autogo hook fires on the
#                                                 short final USB transfer and
#                                                 runs the loader -> Linux)
#
# Prereqs on the host:
#   - artifacts built (inside the cascadia-build container):
#       docker run --rm -v "$PWD":/work -w /work cascadia-build bash scripts/build-chain-k93.sh
#       docker run --rm -v "$PWD":/work -w /work cascadia-build bash scripts/build-kernel-k93.sh
#       docker run --rm -v "$PWD":/work -w /work cascadia-build bash scripts/build-staging-k93.sh
#   - host tools (irecovery + kloader): fetched automatically by
#     scripts/fetch-tools-k93.sh on first run.  No Legacy-iOS-Kit checkout is
#     needed for the default path (only for --kdfu-lik).
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIK="${LIK:-$HOME/Legacy-iOS-Kit}"
FW="$ROOT/build/adt-k93ap"
OUT="$ROOT/build/out"

IBEC="$FW/iBEC.k93.autogo.plain.dfu"
BUNDLE="$OUT/staging-bundle.bin"
LOADER="$OUT/linux-boot.bin"

PWN_MODE=kdfu
WANT_UART=1
UART_DEV="${UART_DEV:-}"
SUDO="${SUDO:-}"   # empty by default: libusb reaches the iPad without root on
                   # this host.  Set SUDO=sudo if your udev rules require it.

while [ $# -gt 0 ]; do
    case "$1" in
        --kdfu)     PWN_MODE=kdfu; shift ;;
        --kdfu-lik) PWN_MODE=kdfu-lik; shift ;;
        --skip-pwn) PWN_MODE=none; shift ;;
        --no-uart)  WANT_UART=0; shift ;;
        --ibec)     IBEC="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

fail() { echo "error: $*" >&2; exit 1; }
as_root() { if [ -n "$SUDO" ]; then "$SUDO" "$@"; else "$@"; fi; }

# device mode from the USB bus (same detection as Legacy iOS Kit on Linux:
# product id 1227 = DFU/kDFU, 1281 = Recovery, 12xx = normal)
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

udev_hint() {
    cat >&2 <<'EOF'
Raw USB access to the iPad was denied.  Install the libirecovery udev rule once:

    echo 'SUBSYSTEM=="usb", ATTR{idVendor}=="05ac", MODE:="0666", TAG+="uaccess"' \
        | sudo tee /lib/udev/rules.d/39-libirecovery.rules
    sudo udevadm control --reload-rules && sudo udevadm trigger

then re-run this script (or set SUDO=sudo to run the tools as root).
EOF
}

echo "== ipad-rea boot-linux.sh (k93ap, kDFU route) =="

for f in "$IBEC" "$BUNDLE" "$LOADER"; do
    [ -f "$f" ] || fail "missing artifact: $f
    build first (in the cascadia-build container):
      bash scripts/build-chain-k93.sh && bash scripts/build-staging-k93.sh"
done

# ---------------------------------------------------------------- irecovery --
IRECOVERY="$(command -v irecovery 2>/dev/null || true)"
if [ -z "$IRECOVERY" ] && [ -x "$LIK/bin/irecovery" ]; then
    IRECOVERY="$LIK/bin/irecovery"
fi
if [ -z "$IRECOVERY" ] && [ ! -x "$ROOT/build/tools/irecovery/irecovery" ]; then
    echo "==> no irecovery found — fetching host tools (scripts/fetch-tools-k93.sh)"
    bash "$ROOT/scripts/fetch-tools-k93.sh"
fi
if [ -z "$IRECOVERY" ]; then
    IRECOVERY="$ROOT/build/tools/irecovery/irecovery"
fi
[ -x "$IRECOVERY" ] || fail "no irecovery: not on PATH, not at $LIK/bin/irecovery,
    and scripts/fetch-tools-k93.sh did not install one"

# Optional UART capture (dock-connector serial, docs/uart-console.md).
CAP=""
if [ "$WANT_UART" = 1 ] && [ -n "$UART_DEV" ] && [ -c "$UART_DEV" ]; then
    LOG="$ROOT/build/uart-linux.log"
    mkdir -p "$ROOT/build"
    dd if="$UART_DEV" of="$LOG" bs=4096 status=none &
    CAP=$!
    echo "==> capturing UART: $UART_DEV -> $LOG (pid $CAP)"
fi

# ---------------------------------------------------------------- pwn -----
case "$PWN_MODE" in
    kdfu)
        echo "==> kDFU: $ROOT/boot/enter-kdfu.sh (ssh + kloader; no LIK checkout needed)"
        echo "    The iPad must be on, jailbroken (your semitethered script or"
        echo "    EverPwnage), OpenSSH installed, unlocked, and plugged into USB."
        bash "$ROOT/boot/enter-kdfu.sh"
        echo "==> device is in kDFU"
        ;;
    kdfu-lik)
        [ -x "$LIK/restore.sh" ] || fail "no $LIK/restore.sh — clone Legacy iOS Kit:
    git clone --depth 1 https://github.com/LukeZGD/Legacy-iOS-Kit $LIK"
        echo "==> kDFU: $LIK/restore.sh --kdfu (interactive — follow its prompts)"
        echo "    The iPad must be on, jailbroken (EverPwnage) and connected by USB."
        echo "    It reboots into DFU: the screen goes black and the device shows"
        echo "    up as 'Apple Mobile Device (DFU Mode)' 05ac:1227."
        # restore.sh resolves its own resources relatively, so it has to run
        # from its own directory.  It is interactive by design — it will say
        # what to do with the device — so it is not piped or backgrounded.
        ( cd "$LIK" && ./restore.sh --kdfu )
        # restore.sh returning is not the device being in kDFU.  On its first
        # run on Linux it installs its own dependencies instead, says "run the
        # script again", and exits — with success — having never touched the
        # device.  So ask the device, the same way restore.sh itself checks.
        echo "==> waiting for the device in DFU (kDFU)"
        indfu=0
        for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
            [ "$(dev_mode)" = dfu ] && { indfu=1; break; }
            sleep 1
        done
        if [ "$indfu" = 0 ]; then
            fail "Legacy iOS Kit returned, but no device is in DFU mode — kloader never ran.
Scroll up to its output.  The usual cause is a first run on Linux: it installs
its own dependencies instead, says \"run the script again\" and exits without
touching the device.  Run it once on its own until it reaches its menu, then
run this script again:
    cd $LIK && ./restore.sh"
        fi
        echo "==> device is in kDFU"
        ;;
    none)
        echo "==> skipping the pwn step (--skip-pwn)"
        ;;
esac

# after the pwn step the device must be on the bus as DFU (05ac:1227)
if [ "$(dev_mode)" != dfu ]; then
    fail "device is not in DFU (mode: $(dev_mode)) — cannot upload the iBEC"
fi

# --------------------------------------------------------------- upload ----
echo "==> iBEC:   $IBEC"
as_root "$IRECOVERY" -f "$IBEC" || { udev_hint; fail "iBEC upload failed"; }
sleep 1

# An iBEC upload always "succeeds": it means the host finished sending, not
# that anything is still listening.  Ask the device what it is before throwing
# 11 MB at it, so an iBEC that never came up is reported as that, and not as a
# failed bundle upload three lines later.  A warning rather than an error.
echo "==> waiting for the iBEC to come up in Recovery"
back=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ "$(dev_mode)" = recovery ] && { back=1; break; }
    sleep 1
done
if [ "$back" = 0 ]; then
    echo "    it did not.  The device is: $(dev_mode)" >&2
    case "$IBEC" in
        *.plain.dfu)
            echo "    The image was already the unencrypted one, so it is not the KBAG." >&2
            echo "    The UART capture and the screen are where to look next." >&2 ;;
        *)
            echo "    This is usually an ENCRYPTED iBEC: once iOS has booted the AES GID" >&2
            echo "    key is gone, the KBAG decrypts to nothing, and the iBSS jumps into" >&2
            echo "    garbage.  Over kDFU use the plaintext image:" >&2
            echo "      $FW/iBEC.k93.autogo.plain.dfu" >&2 ;;
    esac
fi

echo "==> bundle: $BUNDLE"
as_root "$IRECOVERY" -f "$BUNDLE" || { udev_hint; fail "bundle upload failed"; }
sleep 1
# Fallback in case the autogo hook did not fire: the loader alone at
# 0x80000000 (needs a manual `irecovery -c go` to run — the bundle path does
# not).  Harmless if Linux already booted: the device is a USB gadget then,
# not recovery, and this upload simply finds nothing to talk to.
as_root "$IRECOVERY" -f "$LOADER" 2>/dev/null || true

[ -n "$CAP" ] && { sleep 2; kill "$CAP" 2>/dev/null || true; }

echo
echo "==> chain sent.  The autogo iBEC should have fired on the bundle upload's"
echo "    short final transfer and be booting Linux now."
if [ "$WANT_UART" = 1 ] && [ -n "$UART_DEV" ] && [ -c "$UART_DEV" ]; then
    echo "    UART log: $ROOT/build/uart-linux.log (earlycon, then the kernel)"
else
    echo "    For the boot log, attach a 3.3 V USB-TTL to the dock UART"
    echo "    (docs/uart-console.md) and re-run with UART_DEV=/dev/ttyUSB0."
fi
echo "    Build 1 has no rootfs yet: the kernel is expected to panic after"
echo "    'Run /init as init process' fails — that is the current milestone."
echo "    Power+home reboots back into iOS (Linux ran from RAM; the NAND is"
echo "    untouched)."
