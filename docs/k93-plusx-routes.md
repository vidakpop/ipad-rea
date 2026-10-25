# Making kloader executable (+x) on the iPad 2 — the routes that exist

The exec channel (`com.apple.debugserver`, see docs/k93-no-cydia-toolbox.md §5)
launches a program **as root**, but only if the file is executable (+x).  Every
host-driven write channel on iOS 9.3.5 creates files 0644:

- jailed AFC: 0644, and its chmod op returns ENOSYS;
- streaming_zip_conduit: 0644 — all zip mode-metadata variants (per-entry `SZ`
  extra field, `StandardFilePerms`, Version 1/2) are ignored.  Measured; the
  docstring in `tools/zipconduit-push.py` claiming `StandardFilePerms` works is
  wrong and has been corrected;
- idevicebackup2 restore: the one channel that can set modes — see Route 2,
  currently blocked by Find My iPad.

iOS 9.3.5 has almost no userland.  Measured through the debugserver launch
oracle (clean `ENo such file or directory` = the file does not exist):
`/bin/sh`, `/bin/ls`, `/bin/cat`, `/bin/cp`, `/bin/echo`, `/bin/chmod`,
`/usr/bin/plutil`, `/usr/bin/chmod`, `/usr/bin/tar`, `/usr/bin/ditto`,
`/usr/bin/id`, `/usr/bin/env` **do not exist**.  What is visible to
debugserver's launches: `/var/mobile/**`, `/Developer/**` (the mounted
Developer Disk Image), `/usr/lib`, `/usr/libexec`, `/sbin`, and `/bin` (an
empty directory).  `/Applications` is not visible.  Existing Apple binaries
(`/usr/lib/dyld`, `/usr/libexec/xpcproxy`, `/sbin/mount`, the DDI tools) are
*found* but their launch fails with `E<unknown failure>` — the amfi/ptrace
handshake denial on a stock device (syslog: `RNBRunLoopLaunchInferior
DNBProcessLaunch() failed to launch process, unknown failure`).  On a
jailbroken device (amfi patched) that check is expected to pass.

So +x has to come from a channel that sets modes, or from a file that is
already +x (the DDI).

## Route 1 — the mounted Developer Disk Image carries +x files

The DDI is mounted at `/Developer` and preserves the HFS+ modes of the files
inside it (its own `usr/bin/debugserver` is 100775 and lockdownd can exec it —
that is how the debugserver service works at all).  The DDI's `/usr/bin`
contains debugserver, DTDeviceArbitration, iprofiler, ScreenShotr,
XcodeDeviceMonitor and xctest — all 100775.

`build/ddi/kdfu-ddi.dmg` is the stock 9.3-era DDI with two files added
(`usr/bin/kloader` at 100755, `usr/bin/pwnediBSS` at 100644), built with
Legacy-iOS-Kit's `hfsplus`/`dmg` tools:

    cp build/ddi/ddi.img build/ddi/ddi-work.img
    $LIK/hfsplus build/ddi/ddi-work.img add build/tools/kloader usr/bin/kloader
    $LIK/hfsplus build/ddi/ddi-work.img add build/tools/pwnediBSS usr/bin/pwnediBSS
    $LIK/hfsplus build/ddi/ddi-work.img chmod 755 usr/bin/kloader
    $LIK/dmg build build/ddi/ddi-work.img build/ddi/kdfu-ddi.dmg

Measured on stock: mounting it with the original `.signature` fails with
`ImageMountFailed` — also with a free mount slot (after a reboot), so it is
the image itself that is refused: the signature is bound to the image content,
or the rebuilt UDIF differs from the original in a way the iOS 9 mounter
rejects (not yet distinguished; a pristine-rebuild control test is still
pending).  **Untested: mounting it on a jailbroken device** — if the mounter's
signature check goes through amfi, the jailbreak patches it and the mount
will succeed, giving `/Developer/usr/bin/kloader` at 0755.

iOS 9's image mounter has no `UnmountImage` (pymobiledevice3 raises
`UnsupportedCommandError`), and only one Developer image can be mounted at a
time (a second `MountImage` fails with `ImageMountFailed` even for the
original image — measured), so swapping images requires a reboot; the mount
does not survive a reboot anyway.  `tools/ddi-swap.py` automates
unmount (where supported) + upload + mount, with a fallback to the original
image so the device is never left without a DDI (debugserver lives in it).

## Route 2 — patched-backup restore (blocked by Find My iPad for now)

The restore is driven entirely by `Manifest.mbdb`, and the stock backup agent
never includes the `/var/mobile/Media` files we drop ourselves (measured: a
full backup of this iPad contains no `kdfu` records — Media is not part of the
default backup set, only CameraRollDomain/DCIM is).  So a plain
backup/restore cannot re-mode them.  But records can be appended by hand —
`tools/mbdb-add.py` appends a record for `HomeDomain`/`Media/kdfu/kloader`
with mode 0100755 and drops the file bytes into the backup under the right
file id (sha1 of `<domain>-<path>`, the convention idevicebackup2 uses):

    tools/mbdb-add.py build/mb-test add HomeDomain Media/kdfu 040755
    tools/mbdb-add.py build/mb-test add HomeDomain Media/kdfu/kloader 0100755 build/tools/kloader
    tools/mbdb-add.py build/mb-test add HomeDomain Media/kdfu/pwnediBSS 0100644 build/tools/pwnediBSS
    idevicebackup2 restore build/mb-test --no-reboot --skip-apps
    ls -la /tmp/ipad-media/kdfu/    # <- is kloader -rwxr-xr-x ?

Whether backupd honors the mode field on restore is **UNTESTED**: the first
attempt was refused before any file transfer with

    ErrorCode 211: Find My iPhone must be disabled before restoring (MBErrorDomain/211)

a device-side check (the string is not in the idevicebackup2 binary), so any
client hits it.  To use this route, Find My iPad must be disabled on the iPad
(Settings → iCloud → Find My iPad → Off, Apple ID password).  The restore
rewrites the user-data domains from the backup; this device is nearly empty
and iOS 9.3.5 is still TSS-signed, so it is a low-risk operation.

## Route 3 — install an app whose main executable is kloader

`tools/zipconduit-install.py` streams `build/fakeapp/Kdfu.app` (main
executable = kloader) with `InstallTransferredDirectory: true`; installd then
marks the main executable 0755 in the app's container.  On stock the install
is rejected at signature verification (`0xe800801c` — this is the jailbreak
probe).  On a jailbroken device (amfi patched) the signature check may pass
and only provisioning may fail — **UNTESTED**.  If the install succeeds, the
executable is at `/var/mobile/Containers/Bundle/Application/<uuid>/Kdfu.app/Kdfu`
and can be launched through debugserver like any other path.

## Route 4 — run our own code inside a DDI tool (xctest); needs an armv7 dylib

`/Developer/usr/bin/xctest` is designed to dlopen third-party code (test
bundles).  A `.xctest` bundle under `/var/mobile/Media/kdfu/` whose executable
is an armv7 dylib with a constructor calling
`chmod("/var/mobile/Media/kdfu/kloader", 0755)` would give +x with no other
channel — but building an armv7-apple-ios dylib needs a cross clang (none
installed).  Also untested: whether xctest launches via debugserver once the
jailbreak patches amfi.  Lowest priority of the four.

## Route 5 — GDB-RSP injection into a launched Apple binary

debugserver's inferior is stopped at its entry point; the RSP `M`/`P`/`G`
packets can write memory and registers, so kloader's Mach-O segments could be
loaded into any launchable +x Apple binary (e.g. `/Developer/usr/bin/xctest`)
and its entry point called with a hand-built argv — no +x needed on our files
at all.  The most work of the routes; kept as the last resort.

## Runbook

Once the jailbreak is active, `boot/enter-kdfu-nossy.sh` runs the whole entry
chain with no ssh/Cydia: jailbreak probe → stage files → try
`/Developer/usr/bin/kloader` (Route 1) → try `/var/mobile/Media/kdfu/kloader`
(Routes 2/3) → launch as root → poll for kDFU (`05ac:1227`).  Then
`./boot/boot-linux.sh --skip-pwn` boots Linux from RAM.
