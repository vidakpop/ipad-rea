#!/usr/bin/env bash
# serve-books.sh — share PDFs/EPUBs from this PC to the iPad over WiFi.
#
# The iPad's iBooks installs PDFs/EPUBs permanently via Safari: open
# http://<pc-ip>:8000/, tap a book, then "Open in iBooks". The book then
# lives on the iPad (survives reboots; independent of the jailbreak work).
#
# usage:   tools/serve-books.sh [directory]   (default: ~/Documents)
set -u
DIR="${1:-$HOME/Documents}"
[ -d "$DIR" ] || { echo "error: no such directory: $DIR"; exit 1; }

# prefer a real LAN address (192.168.*, 10.*) over VPN/docker/CGNAT ranges
ip="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^(192\.168|10\.)' | head -1)"
[ -n "$ip" ] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"

echo "serving: $DIR"
echo "on the iPad (same WiFi), open in Safari:"
echo "    http://$ip:8000/"
echo "tap a PDF/EPUB -> 'Open in iBooks' — it is saved on the iPad."
echo "press Ctrl-C to stop serving."
cd "$DIR" && exec python3 -m http.server 8000 --bind 0.0.0.0
