# Permanent, software-only jailbreak for the iPad 2 on iOS 9.3.5

Goal: a jailbreak that **survives every reboot** on the iPad 2 (k93ap,
S5L8942, iOS 9.3.5), reached with **no extra hardware** — only the USB cable
and a free Apple ID. That jailbroken state is what lets us enter kDFU and
boot Linux (see [k93-no-cydia-toolbox.md](k93-no-cydia-toolbox.md) and
[k93-boot-linux.md](k93-boot-linux.md)).

This also answers the "bypass the A5 with software only, no hardware" question
for this device. Short version: **the A5 BootROM (DFU) exploit cannot be driven
from a PC**, so the only no-hardware route is a userspace jailbreak. The good
news: for iOS 9.3.5 there is a fully **untethered** one.

---

## 1. Why the A5 DFU exploit (checkm8-a5) needs hardware, not just software

The tempting path is to pwn the A5 in DFU mode over USB (checkm8-a5) and skip
the jailbreak entirely. It does **not** work from a normal PC. This is not a
"nobody tried" gap; it is a hard USB-protocol requirement, confirmed in the
exploit's own writeup (`a1exdandy/checkm8-a5` README) and by ElcomSoft, whose
tooling is the reason the Pico exists:

> "if we use any normal OS with default USB stack for exploitation, then we
> can't avoid standard device requests (e.g. `SET_ADDRESS` ...) sent by OS
> before we can work with device. Because of it in our PoC we use `Arduino`
> and `MAX3421E` to control early initialization of USB."
>
> "if we use normal OS with default USB stack, we can't avoid sending of zero
> length packets in status phase of standard device USB control requests."

The A5 exploit needs, in order:

1. a specific sequence of DFU control requests (`ctrlReq(0x21,1,0x40)`,
   `ctrlReq(0x21,1,0)`, `ctrlReq(0xa1,3,1)` x2) to set up a use-after-free of
   the DFU `io_buffer`;
2. an **incomplete HOST2DEVICE control transaction** to latch global state;
3. a **bus reset at an exact moment**.

A PC's OS + xHCI host controller enumerate the device itself (sending
`SET_ADDRESS`, `GET_DESCRIPTOR`, `SET_CONFIGURATION` and zero-length status
packets) and will not let you fire a half-finished control transfer followed
by a precisely-timed reset. You must be the USB **host at the raw-packet level
from the very first packet**, which is what a Pi Pico (RP2040) or an
Arduino + MAX3421E USB Host Shield does. ElcomSoft states the same: every
checkm8 device can be exploited with or without the Pico **except the entire
A5 family** (iPhone 4S, iPad 2/3, iPad mini 1, iPod touch 5, Apple TV 3).

So, **software-only (no hardware) on A5 ⇒ you must jailbreak in userspace.**
The DFU/pwned-DFU step then comes *from* the jailbroken device as kDFU, which
needs no extra hardware at all.

(If you ever do buy a ~$5 Pi Pico, checkm8-a5 gives pwned DFU directly and
skips the jailbreak — but that violates the "no hardware" constraint.)

---

## 2. The software-only path: EverPwnage (untethered, permanent)

[EverPwnage](https://github.com/LukeZGD/EverPwnage) by LukeZGD is an
**untethered** jailbreak for 32-bit devices on **iOS 7.0–9.3.6**.

Supported devices include the **A5(X) family: iPhone 4S; iPad 2, 3, mini 1;
iPod touch 5** — so the iPad 2 (k93ap) on 9.3.5 is covered.

Untether: the app has an **"Install Untether" toggle, ON by default**. For
iOS 9.3.5–9.3.6 it installs the **iocaste** untether (staturnz). EverPwnage
v2.0 made iOS 9.3.5/9.3.6 untethered for the first time.

### Why this is "permanent"

The untether is installed into the system (a boot-time LaunchDaemon) and
re-applies the kernel patch on **every boot**. Once you have jailbroken once
with "Install Untether" ON, the iPad boots jailbroken **forever after** — even
if the sideloaded app's free 7-day signing certificate later expires. The app
is only needed for the *initial* jailbreak/install. That is exactly the
"still works after a restart" behaviour you asked for.

Because the device is then jailbroken on every boot, we can later add a
boot-time LaunchDaemon that runs kloader → kDFU → Linux automatically, so the
iPad boots straight into Linux. That persistence step is future work
(`tools/` already has the no-Cydia toolbox to run kloader over debugserver).

---

## 3. What you need

- The iPad 2 on iOS 9.3.5, unlocked (passcode `3931`), connected by USB.
- Your **free Apple ID** (the one you use for the App Store).
- If you have **two-factor authentication** on that Apple ID, an **app-specific
  password** (generate at https://appleid.apple.com → Sign-In and Security →
  App-Specific Passwords). Sideload tools need this, **not** your main password.
- A Linux PC (yours) with the iPad plugged in.

## 4. Sideload EverPwnage (Linux)

The IPA is already fetched and verified in this repo at
`build/jailbreak/EverPwnage-v2.0.2.ipa` (re-fetch/verify any time with
`scripts/fetch-jailbreak-ipas.sh`).

### Option A — one command (recommended): `scripts/sideload-everpwnage.sh`

This signs + installs EverPwnage fully locally. Your Apple ID credentials are
read from the environment or from a gitignored `.env` in the repo root —
**never paste them into chat**:

```bash
# either:
APPLE_ID=you@example.com \
APPLE_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx \
  ./scripts/sideload-everpwnage.sh
# or: put the same two lines in .env (gitignored) and just run the script
./scripts/sideload-everpwnage.sh
```

`APPLE_APP_PASSWORD` must be an **app-specific password** from
https://appleid.apple.com (Sign-In & Security → App-Specific Passwords) — **not**
your main Apple ID password — generated while signed in as the **same** Apple ID
you pass as `APPLE_ID`. A free Apple ID works; the 7-day cert is fine because
the jailbreak is untethered and persists after the app expires.

The script: starts a **local anisette server** (`tools/anisette-server.py`,
Anisette.py engine) → runs **AltServer-NG** (jaakkopalvaila's AltServer-Linux
fork with the October-2026 sign-in fixes) against it → signs the IPA, registers
the iPad, installs it, then prints the installed-app list. Needs the iPad
plugged in, unlocked, and trusted.

#### Why this exact stack (October 2026 Apple breakage)

Apple broke Apple-ID sign-in for **all** free sideload tools twice in 2026:

* **September 2026:** `gsa.apple.com` answers **HTTP 503** to any sign-in whose
  `X-Mme-Client-Info` contains `com.apple.dt.Xcode` — this killed AltServer,
  AltStore and SideStore at once.
* **2026-10-12/13:** Apple rejects sign-ins where the client identity does not
  match the anisette platform (**-80045** "This action cannot be completed at
  this time"), and Android-anisette (AnisetteKit / Apple-Music-APK libraries)
  gets HTTP 503. This killed Sideloadly, SideStore, iloader and plumesign at
  once. Public "remote anisette" servers (ani.sidestore.app, ani.f1sh.me,
  armconverter.com, …) are flagged/dead — using one is why older tools now fail
  even with a correct password.

The working combination (verified 2026-10-25):

1. **Local anisette** generated from Apple's own libraries (Anisette.py /
   `libstoreservicescore.so` + `libCoreADI.so` extracted from the Apple Music
   Android APK) — not a flagged public server. Served by
   `tools/anisette-server.py` with `X-Apple-I-Client-Time` in strict UTC
   `YYYY-MM-DDTHH:MM:SSZ` form (AltServer rejects offset-suffixed times).
2. **AltServer-NG** (`ng-2026-10-20` release), which sends the **Windows-iTunes
   client identity** `<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1
   (com.apple.iTunes/12.12.4.1)>` (the only identity Apple currently accepts for
   GrandSlam sign-in), uses fresh connections per GSA request, and prompts for
   2FA codes.
3. Correct credentials (see troubleshooting below).

`plumesign`, stock `AltServer-Linux` (NyaMisty v0.0.5), Cydia Impactor and
Sideloadly ≤0.70.x all predate these fixes and will fail with -80045 / 503 /
-22406 even when the password is correct.

Or use a GUI tool instead:

### Option B — Sideloadly (GUI)
1. Download Sideloadly for Linux from https://sideloadly.io/ and open it.
2. Drag `build/jailbreak/EverPwnage-v2.0.2.ipa` into Sideloadly (or Device →
   Install IPA / `sideloadly install`).
3. Enter your **Apple ID email** and **app-specific password**.
4. Wait for "Done". The **EverPwnage** app appears on the iPad home screen.

### Option C — Cydia Impactor (GUI)
1. Download Cydia Impactor for Linux from https://cydiaimpactor.com/ .
2. Device → Install Package → select `EverPwnage-v2.0.2.ipa`.
3. Enter Apple ID + **app-specific password** (not your main password).

### Option D — Legacy iOS Kit (interactive, one tool does everything)
The "Sideload IPA" option on the main menu sideloads with your Apple ID. You
said this didn't work for you before — if the sideload step is what failed,
the usual cause is entering the **main** Apple ID password instead of an
**app-specific** one (required when 2FA is on). Retry with an app-specific
password; that is the #1 fix.

> Free Apple ID = the app is signed for 7 days. That is fine: the jailbreak is
> untethered, so it persists after the app expires. You only re-sideload if you
> ever fully restore the iPad.

### Troubleshooting: Apple rejects the password ("Enter the correct password")

If `scripts/sideload-everpwnage.sh` fails with Apple's
`Enter the correct password for this Apple Account (-22406)`, Apple is
rejecting the **credential itself** — the tooling is fine at that point (the
sign-in reached Apple and was processed; a broken tool would fail earlier with
-80045 or HTTP 503 instead).

You can tell "wrong password" apart from "wrong Apple ID" by testing with a
throwaway email: a **non-existent** Apple ID fails with **-20970**, while an
**existing** Apple ID with a bad password fails with **-22406**. So:

* `-22406` → the Apple ID exists, the password is wrong for it.
* `-20970` → the email is not an Apple ID (typo, or wrong account).

Causes of -22406, in order of likelihood:

1. **A one-character copy/paste slip** in the app-specific password (it still
   looks right: 19 chars, `xxxx-xxxx-xxxx-xxxx`).
2. **Generated under a different Apple ID.** App-specific passwords are tied to
   the account — it must be generated while signed in as the same Apple ID used
   for `APPLE_ID`.
3. **Changing the Apple ID password revokes ALL app-specific passwords.** If the
   main password was changed (by you, or by Apple after a security event), every
   previously generated app-specific password is dead.
4. **Security hold** from repeated failed sign-ins (yours and the script's).

Fix: sign in to https://appleid.apple.com with the Apple ID + **main** password +
2FA, confirm the signed-in account is the same one you pass as `APPLE_ID`,
clear any security alert, then **App-Specific Passwords → revoke old → generate
a new one**, copy it **exactly** (it is shown only once), and put it in `.env`
as `APPLE_APP_PASSWORD`. Then re-run the script.

Alternative that needs no app-specific password: put your **main** Apple ID
password in `.env` instead. Apple will then push a 2FA code to your trusted
devices and the tool will prompt `Enter the code sent to your device` — type the
6-digit code and the sign-in completes.

Other errors you may see:

* `-80045` / HTTP 503 → you are using a pre-October-2026 tool or a flagged
  remote anisette server. Use `scripts/sideload-everpwnage.sh` (local anisette
  + AltServer-NG) instead.
* `-22411` after the password was accepted → Apple sent a 2FA code to your
  trusted devices; the tool needs to prompt for it (AltServer-NG does).
* `0xe8008024` / "provisioning profile is banned" → Apple revoked the
  provisioning profile wave of Sept 2026; retry later or with another Apple ID.

## 5. Jailbreak (on the iPad)

1. Open the **EverPwnage** app on the iPad.
2. Make sure **"Install Untether" is ON** (default).
3. Tap **Jailbreak**. The app runs the exploit (oob_entry) and installs the
   untether. The iPad may respring/reboot.
4. After it reboots, the device is jailbroken **and stays jailbroken** (that is
   the untether doing its job).

> If the exploit fails, just re-open the app and tap Jailbreak again — it can
> take a couple of tries. Do **not** reboot into a half-state; re-run the app.

> Note: a previous Phoenix/other semi-untethered jailbreak is incompatible for
> migration if it used Pangu8/Pangu9/TaiG/PPJailbreak/wtfis. On a clean stock
> 9.3.5 (your case) there is nothing to conflict with.

## 6. Fallback: Phoenix (semi-untethered)

If EverPwnage will not sideload or will not run, use
[Phoenix](https://phoenixpwn.com/) (Siguza & tihmstar) — semi-untethered for
iOS 9.3.5/9.3.6, all 32-bit devices including iPad 2. IPA is staged at
`build/jailbreak/Phoenix6.ipa` (sha256
`d7e5e84e4081b6e138d2f3ed5bb68ff944164e7483a9962c32b08b37e57fa161`).
Sideload the same way, open the **Phœnix** app, tap **Kickstart Jailbreak**.
Difference: Phoenix is semi-untethered, so you must re-open the app after every
reboot. It still gives us the jailbroken state kDFU needs. Prefer EverPwnage.

## 7. Verify, then boot Linux

Once the iPad is jailbroken, tell me (or run the probe yourself):

```bash
# from the repo root; expects the venv at /tmp/p3venv (see toolbox doc §0)
timeout 150 /tmp/p3venv/bin/python -u tools/zipconduit-install.py build/fakeapp/Kdfu.app
```

On a **stock** device this fails with `0xe800801c (No code signature found)`.
On a **jailbroken** device the outcome changes (install proceeds or fails with a
*different* error) — that change is the jailbreak confirmation.

Then the full no-Cydia runbook takes over:
[docs/k93-no-cydia-toolbox.md](k93-no-cydia-toolbox.md) §7 — stage kloader +
pwnediBSS, launch kloader over debugserver → kDFU → `boot/boot-linux.sh`.

## 8. Staged jailbreak IPAs

| File | Jailbreak | Type | Devices | sha256 |
|---|---|---|---|---|
| `build/jailbreak/EverPwnage-v2.0.2.ipa` | EverPwnage v2.0.2 | **untethered** | 32-bit, iOS 7.0–9.3.6 (incl. iPad 2) | `8e4d364f512e26492c36d65900003045f7da3068580fc8ef9a8d2a36baec11d7` |
| `build/jailbreak/Phoenix6.ipa` | Phoenix 6 | semi-untethered | 32-bit, iOS 9.3.5–9.3.6 (incl. iPad 2) | `d7e5e84e4081b6e138d2f3ed5bb68ff944164e7483a9962c32b08b37e57fa161` |

Both are gitignored build artifacts; `scripts/fetch-jailbreak-ipas.sh`
re-downloads and verifies them.

## 9. Why not just "fully activate" iOS / bypass iCloud

You mentioned wanting the iPad fully usable after a restart. The jailbreak
above already gives you a permanently jailbroken iOS 9.3.5, which is the
legitimate "usable forever" state: you can install any old 32-bit apps/tweaks
and, more importantly for this project, boot Linux. I won't help with
iCloud activation-lock bypass — and note the Linux boot chain does not depend
on iOS activation at all, so it is not a blocker here.
