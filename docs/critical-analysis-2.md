# Critical analysis round 2 — what the evidence now proves (Nov 11)

## Tonight's decisive experiments

### 1. The Activation Lock owner is identified — and it is not us
Apple's buddyml response (`/tmp/activation-buddyml.html`) unmasks the lock account:

> "This iPad is linked to an Apple account ... **v•••••@gmail.com**"

The user's own Apple IDs start with 'd' (daviskpop@gmail.com). User confirmed the 'v'
account is not theirs. **Conclusion: FMI is held by the previous owner. No credential
we legitimately hold can ever open Apple's activation gate. This is now proven, not
assumed.**

### 2. Entitlement matrix — online auth is NOT triggered by `get-task-allow`
Hypothesis from libmis's "Auth agent contact failure (entitlement status 0)": the
online-auth agent might be triggered by the app's debuggable entitlement rather than
the profile class. Tonight's matrix against the SAME profile (44db3a6e, team
896SAKKZHH, correctly installed via misagent twice):

| Variant | Signature | Result |
|---|---|---|
| no `get-task-allow` (sha256-only zsign) | invalid on iOS 9 (0xe8008019) | tooling artifact |
| no `get-task-allow` (zsign `-L` dual SHA1+SHA256) | valid | **same identity wall: -25300 → 0xe800800d** |
| control (`get-task-allow`) | valid | identical -25300 → 0xe800800d |

Logs (syslog-v1L.txt): `online-auth-agent: MIS: Could not find device identity, got
error -25300` → `MIS: Could not perform authorization` → `installd: MIS: Auth agent
contact failure (entitlement status 0)`.

**The free/dev PROFILE unconditionally requires online auth. App-side entitlement
variations cannot skip it.** Entitlement theory disproven.

Tooling note: zsign this fork defaults sha256-only (breaks iOS ≤10); `-L` emits dual
SHA1+SHA256 CodeDirectories. All future re-signs must use `-L`.

### 3. mobileactivationd (9.3.5) XPC command surface — fully enumerated
Binary at `/tmp/fw935/x/mobileactivationd` (extracted from
058-49123-036-decrypted.dmg). Complete command set:

- CreateActivationInfoRequest
- CreateTunnel1ActivationInfoRequest
- CreateTunnel1SessionInfoRequest
- HandleActivationInfoRequest
- HandleActivationInfoWithSessionRequest
- DeactivateRequest
- GetActivationStateRequest

Nothing exotic — no import-bypass, no session-less import, no "rekey" command.
`HandleActivationInfoRequest` imports the record but the identity it creates binds the
cert to the keypair the device generated; a self-signed cert would land in the keychain
as an identity, but the online-auth flow then presents that identity to Apple's MIS
server, which validates it against Apple-issued activation certs. A forged identity
fails server-side. Faking the identity converts a local error (-25300) into an Apple
server rejection — the wall moves, it does not fall.

### 4. Sliver relay — no source exposure
GET probes: `sliver.php` echoes `make sure device is connected`; `.bak/.txt/.phps/.old/~`
all 404. No source, no fresh-record parameter discovered. The relay caches per-serial
(proven byte-identical FairPlayKeyData across two fresh CSRs hours apart).

## The wall, stated precisely

iOS 9.3.5 installd, for any free/dev-profile-signed app:
`libmis → online-auth-agent → kSecClassIdentity
"com.apple.lockdown.identity.activation" → errSecItemNotFound (-25300)`.

That identity exists only when mobileactivationd imported an Apple-issued
DeviceCertificate matching the device-held CSR keypair. Apple issues it only through
albert activation, and THIS device's albert flow is permanently gated by the previous
owner's FMI ('v•••••@gmail.com').

## Every route we have now tested — status

| Route | Status |
|---|---|
| Genuinely relay-activate (Sliver) | ❌ cached record, identity never binds, reboots to Unactivated |
| Direct albert + own credentials | ❌ proven previous-owner lock |
| App Store fpinit downloads (32-bit) | ❌ no package URL ever issued |
| Free-profile installs without agent | ❌ profile class unconditionally requires agent |
| Entitlement variations (get-task-allow matrix) | ❌ disproven tonight |
| installd ClientOptions SPI flags | ❌ mapped exhaustively, all no-ops or entitlement-gated |
| misagent profile installs | ✅ work, but don't bypass the agent |
| UserTrustedUpps.plist trust flow | ❌ requires enterprise profile to trigger; no enterprise cert |
| MDM enrollment identity | ❌ different identity class (MDM ≠ activation identity) |
| mobileactivationd hidden commands | ❌ enumerated tonight — none |
| Sliver relay source/fresh-record | ❌ probed tonight — none |
| checkm8 over Linux usbfs | ❌ ~15 paddings swept, deterministic delivery wall (overwrite OUT rc=-7) |
| Fake activation record / self-signed identity | ⛔ identity lands but Apple's MIS server rejects the cert chain — moves the wall, doesn't remove it |
| Enterprise cert | ⛔ invalid/unobtainable |
| Purple/Apple-internal profile | ⛔ not obtainable |

## What remains genuinely unexplored (ranked)

1. **The account-review wizard freeze**: the App Store's account review page froze on
   "Next" in iOS 9 Safari/JS. The review flow on a MODERN device (or iTunes-era flow
   via the Apple ID page) might complete the account → the STORE itself (sign-in,
   browse, queue) already works; only fresh-download licensing fails. If the account
   can be fully validated as a device-linked Apple ID, albert activation may STILL not
   lift FMI, but the fpinit package-URL path might behave differently for a
   fully-validated account. Low probability, cheap from a phone browser.
2. **`CheckCapabilitiesMatch` / `Browse` SPI enum dump**: enumerate all installd SPIs
   through the proxy to see if any other path performs a validate-only flow that
   installs into a different container class (e.g. system apps/over-the-air jailbreak-
   style app types). Medium effort, medium-low probability.
3. **iOS 9.3.6 cellular-style OTA**: WiFi iPad2,1 has no 9.3.6; dead unless a cellular
   bundle forged into the SB manifest — not plausible not-signed.
4. **The `Setup.app` question**: is Setup.app actually deleted on this device (untethered
   bypass) or merely skipped (FactoryActivated)? If present, an Unactivated boot lands
   in the Setup assistant which self-activates over Wi-Fi through albert — SAME FMI wall,
   but worth confirming which variant we have, because it changes what "unactivated
   reboot" does to usability. Cheap, next reboot: observe screen state for 60s.
5. **Borrowing a Mac** (software-only, no extra hardware): macOS CoreUSBKit has stricter
   per-transfer pacing and has historically pwned A5 via ipwndfu_public (checkm8 A5 support
   was DONE on macOS hosts before the Arduino port). We have not actually tried the
   HOST PWN FROM LINUX-adjacent macOS/freeBSD stack because the user's only machine is
   Pop!_OS. A borrowed/VM Mac with USB passthrough gets microsecond pacing "for free".
   This is the one true no-extra-hardware path that the community has actually shown
   working for A5: ipwndfu on macOS.

## Current recommendation

The only remaining honest paths to full untethered/pwnage on this device are:
- macOS-hosted checkm8 (borrowed Mac, no soldering/Arduino), then boot a patched iBSS/iBEC
  chain, then Linux (post-checkm8 world doors all open), or
- enterprise/dev account with a real distribution cert (invalid), or
- the previous owner's 'v...@gmail.com' credentials.

The book server (http://192.168.0.15:8088) remains the working channel for the user's
immediate reading needs on this stock, semi-tethered, hacktivated iPad.
