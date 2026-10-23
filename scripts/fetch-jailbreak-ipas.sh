#!/usr/bin/env bash
# Fetch + sha256-verify the jailbreak IPAs used to permanently jailbreak the
# iPad 2 on iOS 9.3.5 (no extra hardware). See docs/k93-permanent-jailbreak.md.
#
#   EverPwnage-v2.0.2.ipa  -> untethered (permanent) jailbreak  [PRIMARY]
#   Phoenix6.ipa           -> semi-untethered jailbreak          [fallback]
#
# Output goes to build/jailbreak/ (gitignored). Re-running is safe; a file is
# only re-downloaded if it is missing or fails the hash check.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/build/jailbreak"
mkdir -p "$DEST"

# name | url | sha256
fetch() {
  local name="$1" url="$2" want="$3"
  local out="$DEST/$name"
  if [[ -f "$out" ]] && [[ "$(sha256sum "$out" | awk '{print $1}')" == "$want" ]]; then
    echo "[ok]   $name already present and hash-verified"
    return 0
  fi
  echo "[..]   downloading $name"
  curl -fL --retry 3 -o "$out" "$url"
  local got
  got="$(sha256sum "$out" | awk '{print $1}')"
  if [[ "$got" != "$want" ]]; then
    echo "[FAIL] $name hash mismatch" >&2
    echo "       want $want" >&2
    echo "       got  $got" >&2
    rm -f "$out"
    return 1
  fi
  echo "[ok]   $name verified ($got)"
}

fetch EverPwnage-v2.0.2.ipa \
  "https://github.com/LukeZGD/EverPwnage/releases/download/v2.0.2/EverPwnage-v2.0.2.ipa" \
  "8e4d364f512e26492c36d65900003045f7da3068580fc8ef9a8d2a36baec11d7"

# Phoenix6.ipa: the official site gates download.php behind a browser
# User-Agent + Referer; supply both so plain curl works.
fetch_phoenix() {
  local name="Phoenix6.ipa"
  local url="https://phoenixpwn.com/download.php"
  local want="d7e5e84e4081b6e138d2f3ed5bb68ff944164e7483a9962c32b08b37e57fa161"
  local out="$DEST/$name"
  if [[ -f "$out" ]] && [[ "$(sha256sum "$out" | awk '{print $1}')" == "$want" ]]; then
    echo "[ok]   $name already present and hash-verified"
    return 0
  fi
  echo "[..]   downloading $name"
  curl -fL --retry 3 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36" \
    -e "https://phoenixpwn.com/" \
    -o "$out" "$url"
  local got
  got="$(sha256sum "$out" | awk '{print $1}')"
  if [[ "$got" != "$want" ]]; then
    echo "[FAIL] $name hash mismatch" >&2
    echo "       want $want" >&2
    echo "       got  $got" >&2
    rm -f "$out"
    return 1
  fi
  echo "[ok]   $name verified ($got)"
}
fetch_phoenix

echo
echo "Staged in $DEST:"
ls -la "$DEST"
echo
echo "Next: sideload EverPwnage-v2.0.2.ipa (Sideloadly / Cydia Impactor / Legacy"
echo "iOS Kit) with your Apple ID + app-specific password, then open the app and"
echo "jailbreak with 'Install Untether' ON. See docs/k93-permanent-jailbreak.md."
