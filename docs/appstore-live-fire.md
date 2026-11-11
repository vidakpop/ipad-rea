# App Store live-fire diagnostic — Nov 11 evening (final store status)

## What works on the hacktivated iPad 2 (proven live)

- **Account sign-in**: fully works (akd `success` x2 per attempt,
  account active, id 22785038708). Settings-iCloud sign-in may hang
  its wizard; the iTunes & App Store sign-in completes.
- **Browsing/search**: works (search.itunes/apple + mzstatic assets
  fetched fine).
- **Purchase queueing**: works server-side — Thyme (`no.hyper.thyme`)
  purchases auto- arrived and retried on the device queue.

## What is broken (all evidence in /tmp/mitm-*.log + syslog)

1. **Download licensing** — the killer. Per attempt:
   - placeholder `.app` installs via installd (works)
   - `itunesstored: Could not load library [21]` (~4 s after placeholder)
   - fpinit.itunes.apple.com + buy/sp/p29-buy connect then drop
   - **package servers (mzstatic package/download hosts) are NEVER
     contacted** — no license grant, no package URL
   - ~15 s later itunesstored uninstalls the placeholder; App Store
     may then show the "review/complete your account" wizard
2. **The account-review wizard freezes on Next** — it is rendered
   from 2026 server JS (`finance-app.itunes.apple.com/vendor-*.js`),
   which errors in the 2016 JavaScriptCore
   (`Application Router: error from processRedirectUrl`, plus ITML
   `Can't dispatch event` DOM errors). It will never complete on
   iOS 9.
3. **User-installed root CAs are IGNORED by store daemons** —
   tested with a profile-installed mitmproxy CA: Safari trusts it,
   itunesstored/AppStore drop the TLS handshake anyway (system
   anchors only). Plaintext capture of licensing is impossible
   without jailbreak.

## Diagnosis

- Apple's 2026 store backends dropped support for the 2016
  licensing client handshake. Sign-in/browsing/search were never
  cut off, but free-app **download licenses are no longer granted**
  to the iOS 9.3.5 client — the store dies at fpinit, before any
  package URL is issued. The `Could not load library [21]` warning
  (iTunesStore weak-framework loader, `ISWeakLibraryLoaded`; refs
  unresolvable in static RE) accompanies every abort.
- This matches the mixed 2025-2026 community state: "32-bit App
  Store still working" applies to sign-in/browsing; actual fresh
  downloads are failing on 9.3.x.

## One last untested path

- **Purchased-tab cloud download** of an already-owned app
  (different licensing path than a fresh purchase). Expected to hit
  the same fpinit wall, but worth one attempt while signed in.

## Session tools state

- mitmproxy passthrough on :8080 (to be turned off; user should set
  iPad Wi-Fi HTTP proxy back to Off)
- cert profile "Davis Debugging CA" installed on iPad (user may
  remove it via Settings > General > Profiles)
- idevicesyslog capture watchdog pattern documented earlier

## Consequence for the master plan

The "install through the store channel" route delivers **no
third-party apps** on this device. The remaining software-only
levers are unchanged: checkm8 A5 host sweep (needs DFU), or full
research-grade chains (Safari/parser bugs — months). Books/PDF via
LAN server + iBooks remains the working user-value path.
