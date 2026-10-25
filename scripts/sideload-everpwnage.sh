#!/usr/bin/env bash
# Sideload the EverPwnage UNTETHERED jailbreak onto the iPad 2 (iOS 9.3.5)
# WITHOUT Legacy iOS Kit, using only local tools:
#
#   1. local anisette server (tools/anisette-server.py, Anisette.py engine)
#      -> avoids Apple's flagged/rejected public remote anisette servers
#   2. AltServer-NG (jaakkopalvaila's AltServer-Linux fork with the
#      October-2026 sign-in fixes: Windows-iTunes client identity, fresh
#      GSA connections, 2FA prompt support)
#   3. it signs EverPwnage-v2.0.2.ipa with your (free) Apple ID, registers
#      the iPad, and installs the signed IPA over USB
#
# CREDENTIALS ARE NEVER ECHOED OR WRITTEN TO DISK BY THIS SCRIPT.
# They come from the environment, or from a local .env file (gitignored):
#
#   APPLE_ID=you@example.com \
#   APPLE_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx \
#     ./scripts/sideload-everpwnage.sh
#
# APPLE_APP_PASSWORD must be an APP-SPECIFIC password generated at
# https://appleid.apple.com (Sign-In & Security -> App-Specific Passwords),
# minted while signed in as the SAME Apple ID you pass here. If your account
# has two-factor auth, your MAIN password will not work — Apple will push a
# 2FA code to your trusted devices and the tool will ask for it; that path
# also works (type the code when prompted).
#
# NOTE (Oct 2026): Apple broke sign-in for ALL free sideload tools on
# 2026-10-12/13 (-80045 / HTTP 503). Using anything older than AltServer-NG
# plus a LOCAL anisette server will fail. See docs/k93-permanent-jailbreak.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UDID="${UDID:-ae85db46b1dd7faa563fc6eb53780515a67dfcc7}"
IPA="$ROOT/build/jailbreak/EverPwnage-v2.0.2.ipa"
ALT="$ROOT/build/tools/AltServer-NG"
ALT_URL="https://github.com/jaakkopalvaila/AltServer-Linux/releases/download/ng-2026-10-20/AltServer-x86_64"
ANI_PORT="${ANI_PORT:-6969}"
VENV_PY="$ROOT/build/venv/bin/python"

# --- credentials: env first, then local .env (gitignored, never printed) ---
if [[ -z "${APPLE_ID:-}" || -z "${APPLE_APP_PASSWORD:-}" ]]; then
  if [[ -f "$ROOT/.env" ]]; then
    set -a; source "$ROOT/.env"; set +a
  fi
fi
if [[ -z "${APPLE_ID:-}" || -z "${APPLE_APP_PASSWORD:-}" ]]; then
  echo "[FAIL] APPLE_ID and APPLE_APP_PASSWORD are not set." >&2
  echo "       Either export them, or put them in $ROOT/.env (gitignored):" >&2
  echo "         APPLE_ID=you@example.com" >&2
  echo "         APPLE_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx   # app-specific password" >&2
  echo "       Do NOT paste them in chat." >&2
  exit 2
fi
# never let the password leak into logs: scrub it from all further output
scrub() { sed "s|${APPLE_APP_PASSWORD}|<REDACTED-PW>|g"; }

[[ -f "$IPA" ]] || { echo "[FAIL] Missing $IPA — run: ./scripts/fetch-jailbreak-ipas.sh" >&2; exit 1; }

# --- sanity: iPad connected + trusted ---
if ! ideviceinfo -u "$UDID" -k UniqueDeviceID >/dev/null 2>&1; then
  echo "[FAIL] iPad not detected at UDID $UDID." >&2
  echo "       Plug it in, unlock it, and tap 'Trust' on the iPad if prompted." >&2
  exit 1
fi
echo "[ok] iPad detected: $(ideviceinfo -u "$UDID" -k ProductVersion | tr -d '\n') (UDID $UDID)"

# --- ensure the python venv with Anisette.py ---
if [[ ! -x "$VENV_PY" ]]; then
  echo "[..] creating build/venv"
  python3 -m venv "$ROOT/build/venv"
fi
if ! "$VENV_PY" -c "import anisette" >/dev/null 2>&1; then
  echo "[..] installing Anisette.py (local anisette engine) into build/venv"
  "$VENV_PY" -m pip install -q "Anisette[cli]"
fi

# --- ensure an anisette session exists (downloads Apple Music APK libs once) ---
ANI_DIR="$ROOT/build/anisette-config/anisette-py"
if [[ ! -f "$ANI_DIR/libs.bin" || ! -f "$ANI_DIR/default.prov" ]]; then
  echo "[..] creating anisette session (one-time download of Apple libs, ~2MB)"
  XDG_CONFIG_HOME="$ROOT/build/anisette-config" "$ROOT/build/venv/bin/anisette" new default
fi

# --- ensure the local anisette server is running ---
if ! curl -sf -o /dev/null "http://127.0.0.1:${ANI_PORT}/"; then
  echo "[..] starting local anisette server on 127.0.0.1:${ANI_PORT}"
  nohup "$VENV_PY" "$ROOT/tools/anisette-server.py" --port "$ANI_PORT" \
    > "$ROOT/build/anisette-server.log" 2>&1 &
  for _ in $(seq 1 30); do
    curl -sf -o /dev/null "http://127.0.0.1:${ANI_PORT}/" && break
    sleep 1
  done
fi
if ! curl -sf -o /dev/null "http://127.0.0.1:${ANI_PORT}/"; then
  echo "[FAIL] local anisette server did not come up; see build/anisette-server.log" >&2
  exit 1
fi
echo "[ok] local anisette server: http://127.0.0.1:${ANI_PORT}/"

# --- fetch AltServer-NG if needed ---
mkdir -p "$ROOT/build/tools"
if [[ ! -x "$ALT" ]]; then
  echo "[..] downloading AltServer-NG (October-2026 sign-in fixes)"
  curl -fL --retry 3 -o "$ALT" "$ALT_URL"
  chmod +x "$ALT"
fi

# --- sign + install (talks to Apple; can take ~30-60s) ---
echo "[..] signing + installing EverPwnage as $APPLE_ID (app-specific password)"
echo "     if Apple pushes a 2FA code to your devices, type it when asked"
timeout 280 env ALTSERVER_ANISETTE_SERVER="http://127.0.0.1:${ANI_PORT}" \
  "$ALT" -u "$UDID" -a "$APPLE_ID" -p "$APPLE_APP_PASSWORD" "$IPA" 2>&1 | scrub | tail -25 || true

echo
echo "[..] installed apps on the iPad:"
if ideviceinstaller -u "$UDID" -l 2>/dev/null | grep -qi everpwnage; then
  ideviceinstaller -u "$UDID" -l 2>/dev/null | grep -iE 'everpwnage|CFBundleIdentifier'
  echo
  echo "[done] On the iPad: open the EverPwnage app, keep 'Install Untether' ON,"
  echo "       tap Jailbreak. It resprings/reboots and STAYS jailbroken (untethered)."
  echo "       Then tell me — I'll verify the jailbreak and boot Linux."
else
  echo "       (EverPwnage not listed — install failed; see output above)"
  echo "[FAIL] sideload did not complete. Common causes:"
  echo "       - wrong/typo'd app-specific password (Apple: -22406) — regenerate it"
  echo "         at appleid.apple.com WHILE SIGNED IN AS $APPLE_ID, copy it exactly"
  echo "       - Apple sign-in throttling after repeated attempts — wait ~1h"
  exit 1
fi
