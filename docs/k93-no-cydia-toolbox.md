# The no-Cydia toolbox: host-driven channels on a stock iPad 2 (iOS 9.3.5)

How to talk to the iPad over USB **without Cydia, without OpenSSH, without
AFC2 and without a jailbreak** — and how to tell whether the (semi-tethered)
jailbreak is currently active.

All tools are host-side Python (ctypes against the system libimobiledevice, or
pymobiledevice3 in a venv). No compilation, no sudo, no device-side installs.

## 0. Setup

```sh
python3 -m venv /tmp/p3venv
/tmp/p3venv/bin/pip install pymobiledevice3
```

Everything below assumes the iPad is plugged in, in normal USB mode
(`lsusb` shows `05ac:129f`), and paired.

## 1. Service inventory — `tools/lockdown-probe.py`

```sh
python3 tools/lockdown-probe.py
```

Asks lockdownd to start each candidate service and reports what is reachable.
Measured on this iPad (iOS 9.3.5):

| service | status | notes |
|---|---|---|
| `com.apple.afc` | yes | jailed AFC: only `/var/mobile/Media`, writable, but files are created 0644 and **chmod is ENOSYS** |
| `com.apple.afc2` | **no** (`INVALID_SERVICE`) | the AFC2 tweak is not installed (no Cydia) |
| `com.apple.streaming_zip_conduit` | yes | zip extraction onto the device — see §3 |
| `com.apple.mobile.file_relay` | yes | diagnostic file pull (read-only) |
| `com.apple.mobile.house_arrest` | yes | app-container access (no user apps installed) |
| `com.apple.debugserver` | yes | needs the Developer Disk Image mounted — see §5 |
| `com.apple.mobile.installation_proxy` | yes | app list/install (installs are signature/provisioning-walled) |
| `com.apple.mobilebackup` (v1) | yes | backup/restore — the only *root* file-write channel |
| `com.apple.mobile.mobilebackup2` | **no** | v2 service absent on iOS 9 |
| `com.apple.mobile.diagnostics_relay` | yes | reboot/restart |
| `com.apple.syslog_relay` | yes | system log |
| `com.apple.mobile.mobile_image_mounter` | yes | mounts dmg images (signature-checked) |
| `com.apple.misagent`, `com.apple.pcapd`, `com.apple.crashreportcopymobile`, `com.apple.dt.fetchsymbols` | yes | not useful for this task |

## 2. The "+x problem"

Every host-driven file-write channel on iOS 9 creates files **0644**:

- jailed AFC: 0644, and its chmod op returns ENOSYS;
- streaming_zip_conduit: see §3 — iOS 9's extractor ignores all zip mode
  metadata (per-entry `SZ` extra field, `StandardFilePerms`, Version 1/2
  variants, int/string values — all tested) and lands files at 0644
  (directories 0755).

And `com.apple.debugserver` (the only exec channel) refuses to run anything
that is not executable: launching a 0644 file returns
`EOperation not permitted` — the *same* error as an unsigned binary under
amfi, so on its own it does not distinguish "not +x" from "amfi denied".

Meanwhile `/` is read-only on stock iOS, so a crafted-backup LaunchDaemon
under `/Library/LaunchDaemons` cannot be installed pre-jailbreak either.

## 3. Pushing files: `tools/zipconduit-push.py`

`com.apple.streaming_zip_conduit` extracts a streamed headerless ZIP into
`/var/mobile/Media/<MediaSubdir>/`. Protocol (reverse-engineered; reference
implementation: pymobiledevice3's `StreamingZipConduitService`):

1. send setup plist: `InstallOptionsDictionary`, `InstallTransferredDirectory`
   (false = extract only), `MediaSubdir` (relative to `/var/mobile/Media`),
   `UserInitiatedTransfer`;
2. stream ZIP_STORED local-file-headers + raw data, opened by
   `META-INF/com.apple.ZipMetadata.plist` (RecordCount, StandardDirectoryPerms,
   StandardFilePerms, TotalUncompressedBytes, Version=2 — **Version 1 hangs
   the iOS 9 service**), terminated by a bare `PK\x01\x02`;
3. read plist replies until `Status: DataComplete` or `Error`.

Each connection performs exactly one transfer.

```sh
/tmp/p3venv/bin/python tools/zipconduit-push.py PublicStaging/kdfu \
    build/tools/kloader build/adt-k93ap/iBSS.k93.patched
```

Verify over the jailed AFC mount (`ifuse /tmp/ipad-media`):
`ls -la /tmp/ipad-media/PublicStaging/kdfu/`.

**Path handling, measured:** `MediaSubdir` is resolved and must stay inside
the service's allowed root — `PublicStaging/../kdfu` (→ `/var/mobile/Media/kdfu`)
is accepted, `PublicStaging/../../../../Library/LaunchDaemons` is rejected with
`InvalidPath`. Zip entry *names* are sanitized (`../` neutralised). So the
conduit is a file-drop into `/var/mobile/Media` — same area jailed AFC already
gives us, but without needing the AFC mount, and it survives reboots.

## 4. Jailbreak probe: `tools/zipconduit-install.py`

```sh
/tmp/p3venv/bin/python tools/zipconduit-install.py build/fakeapp/Kdfu.app
```

Streams `build/fakeapp/Kdfu.app` (an .app whose main executable is kloader)
with `InstallTransferredDirectory: true`. The device extracts it, then
installation_proxy tries to install it. The **error type tells you the
jailbreak state**:

- `ApplicationVerificationFailed ... 0xe800801c (No code signature found)` →
  **stock**: amfi is enforcing signatures, the kernel is not patched;
- a *different* error (provisioning) or success → the kernel patch is live
  (amfi patched) — i.e. the semitethered jailbreak **is** active.

This is currently how we know the iPad is stock: the install fails with
`0xe800801c`.

## 5. Executing as root: `tools/debugserver-launch.py`

Mount the Developer Disk Image first (it persists until reboot):

```sh
UDID=ae85db46b1dd7faa563fc6eb53780515a67dfcc7
ideviceimagemounter -u $UDID build/ddi/DeveloperDiskImage.dmg \
    build/ddi/DeveloperDiskImage.dmg.signature
```

```sh
python3 tools/debugserver-launch.py <executable> [args...]
```

Launches a program via `com.apple.debugserver` (same flow as `idevicedebug
run`), as root, and detaches so it keeps running. Measured on iOS 9.3.5:

| target | result | meaning |
|---|---|---|
| `/bin/ls`, `/bin/sh`, `/usr/bin/id`, `/Applications/Calculator.app/Calculator` | `ENo such file or directory` | the root filesystem is **hidden** from debugserver's launches |
| `/var/mobile/Media/.../kloader` (0644) | `EOperation not permitted` | path visible; not executable / amfi |
| `/Developer/usr/bin/xctest`, `iprofiler`, `Library/Daemons/DTFetchSymbols` | `E<unknown failure>` | DDI binaries are *found* but fail a further check |
| `/Developer/usr/bin/nonexistent` | `ENo such file or directory` | control: ENOENT = not visible |
| `/Developer/Applications/MobileReplayer.app/MobileReplayer` | `ELocked` | .app launches hit the passcode-lock check first — unlock the iPad (3931) |

So the exec channel can reach `/var/mobile/**` (and `/Developer/**`), and on a
jailbroken device (amfi patched) a **+x** binary under `/var/mobile` runs as
root. That is the whole game: get kloader +x under `/var/mobile`, launch it
here, and the iPad drops into kDFU.

Note: a *script* payload cannot work — `/bin/sh` is not visible to
debugserver, so only self-contained binaries under `/var/mobile` can be
launched. kloader is exactly that.

## 6. Current state of this iPad (measured 2026-10-23)

- iOS 9.3.5 (13G36), normal USB mode, ActivationState `FactoryActivated`.
- **Not jailbroken right now**: unsigned-app install is rejected at signature
  verification (§4). Consistent with: no sshd, no afc2, debugserver refuses
  unsigned/0644 binaries, and the activation state having changed since the
  semitethered script last ran — a semitethered jailbreak dies with the boot.
- The semitethered script must be re-run for the kernel patch (amfi off) to
  exist; there is no software-only way around this on A5 (checkm8-a5 needs a
  Pi Pico/Arduino; Odysseus also needs kloader on a jailbroken device).

## 7. Runbook once the jailbreak is active

1. Re-run the semitether script (iPad plugged in). **Do not reboot afterwards.**
   Unlock the iPad (passcode 3931) and leave it unlocked.
2. Tell the host. The host then, in order:
   - re-probes the jailbreak (`tools/zipconduit-install.py` — expect a
     non-signature outcome);
   - checks for sshd left by the script (`iproxy 6414 22`);
   - ensures kloader + pwned iBSS are under `/var/mobile/Media/kdfu/`
     (`tools/zipconduit-push.py` — already staged);
   - gets kloader +x (via the script's own channel if it has one, e.g. ssh;
     otherwise via a root file-write during the jailbroken boot);
   - launches it: `python3 tools/debugserver-launch.py \
       /var/mobile/Media/kdfu/kloader /var/mobile/Media/kdfu/pwnediBSS`
     (kloader's argument is the pwned iBSS path on the device);
   - polls `lsusb` for `05ac:1227` — that is kDFU.
3. `./boot/boot-linux.sh --skip-pwn` uploads the autogo iBEC and the staging
   bundle and boots Linux from RAM.
