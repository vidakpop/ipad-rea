#!/usr/bin/env bash
# recovery-exit.sh — escape iOS recovery-mode loop: set auto-boot true + reboot.
# Requires sudo because the USB bulk-write to iBoot needs root on this host.
set -e
E="$(dirname "$0")/../build/Legacy-iOS-Kit/bin/linux/x86_64/irecovery"
if [ "$(id -u)" != 0 ]; then
  exec sudo bash "$0" "$@"
fi
echo "== setting auto-boot=true"
"$E" -c "setenv auto-boot true"
echo "== saving env"
"$E" -c saveenv
echo "== rebooting"
"$E" -c reboot
echo "== done — the iPad should show the Apple logo within seconds"
