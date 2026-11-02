#!/usr/bin/env bash
# usb-mode.sh — show the iPad's current Apple USB mode, optionally watching.
#   tools/usb-mode.sh          print once
#   tools/usb-mode.sh watch    print on every change (0.5 s poll)
# Modes: 05ac:1227 = DFU (checkm8 target), 05ac:1281 = recovery,
#        05ac:12xx = normal iOS.
last=""
while true; do
    line=$(lsusb 2>/dev/null | grep -i '05ac:12' | head -1)
    case "$line" in
        *1227*) mode="DFU (05ac:1227) — checkm8 target" ;;
        *1281*) mode="RECOVERY (05ac:1281)" ;;
        *12*)   mode="NORMAL iOS ($line)" ;;
        *)      mode="none" ;;
    esac
    now="$(date +%T) $mode"
    if [ "$1" = watch ]; then
        [ "$now" != "$last" ] && { echo "$now"; last="$now"; }
        sleep 0.5
    else
        echo "$now"
        break
    fi
done
