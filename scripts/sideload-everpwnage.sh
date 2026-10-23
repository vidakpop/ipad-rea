#!/usr/bin/env bash
# Sideload the EverPwnage UNTETHERED jailbreak onto the iPad 2 (iOS 9.3.5)
# using plumesign (CLI signer, same engine Legacy-iOS-Kit uses).
#
#   1. log in to your Apple ID          (plumesign account login)
#   2. register the iPad with Apple     (plumesign account register-device)
#   3. sign EverPwnage-v2.0.2.ipa        (plumesign sign)
#   4. install the signed IPA           (ideviceinstaller)
#
# CREDENTIALS ARE READ FROM THE ENVIRONMENT. Do NOT paste them into chat.
# Set them in your own terminal, then run this script:
#
#   APPLE_ID=you@icloud.com \
#   APPLE_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx \
#     ./scripts/sideload-everpwnage.sh
#
# APPLE_APP_PASSWORD must be an APP-SPECIFIC password, generated at
# https://appleid.apple.com (Sign-In & Security -> App-Specific Passwords).
# If your Apple ID has two-factor auth, your MAIN password will NOT work here —
# you must use an app-specific password. (This is the #1 reason sideloading
# "doesn't work" with Legacy iOS Kit.)
#
# The script never echoes or writes the password; it is only passed to
# plumesign, which sends it to Apple. A free Apple ID works (7-day cert; the
# jailbreak is untethered so it persists after the app expires).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UDID="${UDID:-ae85db46b1dd7faa563fc6eb53780515a67dfcc7}"
IPA="$ROOT/build/jailbreak/EverPwnage-v2.0.2.ipa"
SIGNED="$ROOT/build/jailbreak/EverPwnage-signed.ipa"
PLUMESIGN="$ROOT/build/tools/plumesign"
PLUMESIGN_URL="https://github.com/claration/impactor/releases/download/v2.7.1/plumesign-linux-x86_64"

# --- credentials from env (never echoed, never written to disk) ---
if [[ -z "${APPLE_ID:-}" || -z "${APPLE_APP_PASSWORD:-}" ]]; then
  echo "[FAIL] APPLE_ID and APPLE_APP_PASSWORD must be set as environment variables." >&2
  echo "       Do NOT paste them in chat. Set them in your terminal, e.g.:" >&2
  echo "         APPLE_ID=you@icloud.com APPLE_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx \\" >&2
  echo "           ./scripts/sideload-everpwnage.sh" >&2
  echo "       Use an APP-SPECIFIC password from appleid.apple.com (not your main password)." >&2
  exit 2
fi

[[ -f "$IPA" ]] || { echo "[FAIL] Missing $IPA — run: ./scripts/fetch-jailbreak-ipas.sh" >&2; exit 1; }

# --- fetch plumesign if needed ---
mkdir -p "$ROOT/build/tools"
if [[ ! -x "$PLUMESIGN" ]]; then
  echo "[..] downloading plumesign (CLI signer)"
  curl -fL --retry 3 -o "$PLUMESIGN" "$PLUMESIGN_URL"
  chmod +x "$PLUMESIGN"
fi

# --- sanity: iPad connected + trusted ---
if ! ideviceinfo -u "$UDID" -k UniqueDeviceID >/dev/null 2>&1; then
  echo "[FAIL] iPad not detected at UDID $UDID." >&2
  echo "       Plug it in, unlock it, and tap 'Trust' on the iPad if prompted." >&2
  exit 1
fi
echo "[ok] iPad detected: $(ideviceinfo -u "$UDID" -k DeviceName | tr -d '\n') ($(ideviceinfo -u "$UDID" -k ProductVersion | tr -d '\n'))"

echo "[..] logging in to Apple as $APPLE_ID (app-specific password)"
"$PLUMESIGN" account login -u "$APPLE_ID" -p "$APPLE_APP_PASSWORD" 2>&1 | grep -vE 'DEBUG|INFO ' || true
# make sure the account we just logged in is the one used for signing
"$PLUMESIGN" account switch "$APPLE_ID" 2>&1 | grep -vE 'DEBUG|INFO ' || true

echo "[..] registering iPad ($UDID) with your Apple ID"
"$PLUMESIGN" account register-device --udid "$UDID" --name "iPad 2" 2>&1 | grep -vE 'DEBUG|INFO ' || true

echo "[..] signing EverPwnage IPA (talks to Apple; can take ~30-60s)"
rm -f "$SIGNED"
"$PLUMESIGN" sign -p "$IPA" --apple-id --udid "$UDID" -o "$SIGNED" 2>&1 | grep -vE 'DEBUG|INFO ' || true
[[ -f "$SIGNED" ]] || { echo "[FAIL] signing produced no output IPA." >&2; exit 1; }
echo "[ok] signed IPA: $SIGNED ($(stat -c%s "$SIGNED") bytes)"

echo "[..] installing signed IPA onto the iPad"
ideviceinstaller -u "$UDID" install "$SIGNED"

echo
echo "[ok] Installed apps now on the iPad:"
ideviceinstaller -u "$UDID" -l 2>/dev/null | grep -iE 'everpwnage|phoenix|CFBundleIdentifier' || true
echo
echo "[done] On the iPad: open the EverPwnage app, keep 'Install Untether' ON,"
echo "       tap Jailbreak. It will respring/reboot and stay jailbroken."
echo "       Then tell me — I'll verify and boot Linux."
