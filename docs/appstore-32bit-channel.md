# The 32-bit App Store channel (Nov 11 research)

## TL;DR

The ONLY install channel left on this hacktivated iPad 2 that does
**not** touch the libmis/online-auth wall is the on-device **App
Store**. Community-verified on Sliver-bypassed devices (r/setupapp):
App Store sign-in works; iCloud sign-in does not.

## Findings (Nov 2026)

1. **32-bit App Store is still alive for iOS 9.3.5.**
   r/LegacyJailbreak "iOS 8-9 App Store is dead" thread: 64-bit iOS
   8/9 devices lost it; **32-bit (iPhone 4S, iPad 2/3, mini 1, touch
   5G) still working** — including explicit "working for me on iOS
   9.3.5 iPad 2" reports.
2. **dashpadd.com Nov 2026 audit**: still installing on iPad 2
   9.3.5: LiveFrame (free), Thyme (free), AVPlayerHD ($2.99),
   Light Alarm ($6.99). Everything else = built-in apps.
3. **r/setupapp on Sliver-bypassed devices** (our exact tool):
   - "If it is sliver untethered, iCloud sign in won't work, should be
     app store only"
   - "You can sign in itunes App Store in settings and whatever app
     you purchase will be available to download on the device"
   - Some devices only install from the **Purchased tab**
     (previously-downloaded list-compatible versions).
   - Known workaround when the App Store *app* refuses sign-in:
     **Settings → iTunes & App Store → sign in there** instead.
4. **Why this dodges our wall**: store apps are FairPlay-signed and
   validated through the storefront receipt path, NOT through
   libmis checkTrustAndAuthorization / online-auth-agent. This is
   consistent with r/setupapp users installing apps fine on
   bypassed devices while every sideloader produces 0xe800800d.

## What it does NOT give us

- Arbitrary code execution. Every store app runs sandboxed with W^X:
  no JIT, no spawning unsigned binaries (the same exec wall we hit
  with debugserver). "Offline C compiler" apps (CppCode etc.) run
  code through interpreters — an interpreted phoenix exploit cannot
  touch the real kernel.
- So the App Store channel = **user-value apps only** (and possibly
  a future parser-bug research target inside legacy apps with
  file-sharing import, e.g. old ffmpeg in AVPlayerHD. Research-grade,
  weeks of work, needs purchase history/payment).

## Concrete test to run on the iPad (5 min)

1. On the iPad: **Settings → iTunes & App Store → Sign In**
   (daviskpop@gmail.com + password; approve 2FA on the phone).
2. Open the **App Store** app → search **Thyme** (free, verified
   still installing Nov 2026) → Get.
3. If direct download fails: check the **Purchased** tab →
   "Not on This iPad" → install a previously-owned app from there.
4. If install succeeds → channel confirmed; report back.
   In parallel our checkm8 DFU sweep remains the jailbreak lever.

## Ready-for-the-moment artifacts

- Phoenix exploit C source (kernel 0-day chain, iOS 9.3.5 32-bit):
  https://gist.github.com/Siguza/96ae6d6806e974199b1d44ffffca5331
  ("Bugs by NSO Group / Ian Beer. Exploit by Siguza & tihmstar.")
  Full source, portable C, our exact platform — runnable the
  instant any code-exec lands (App-store-parser-bug route, checkm8,
  or anything else).
- Decrypted 9.3.5 rootfs at /tmp/fw935/058-49123-036-decrypted.dmg
  → all ARMv7 kernel/symbols offsets available offline.

## Remaining software-only levers (ranked)

1. checkm8 A5 host sweep (existing tool; retry whenever the iPad
   enters DFU; the warp-in stage-3 paddings sweep list is documented).
2. App Store channel (this doc) — user-value + future parser-bug
   research inside store apps.
3. Genuine activation (previous owner — unavailable).
