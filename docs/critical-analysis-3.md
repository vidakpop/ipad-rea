# Critical analysis round 3 — the agent's real endpoint + the closed local surface (Nov 11, late)

## The three overlooked items this round actually examined

### 1. online-auth-agent's server endpoint: `https://ppq.apple.com/v1/authorization`
We always said "the agent talks to Apple" without knowing where. It talks to exactly one
server: ppq.apple.com/v1/authorization — an endpoint Apple STILL actively maintains
(TLS cert renewed **Jan 21 2026**, valid to Feb 2027, public Apple chain: Apple Server
Authentication CA -> Apple Root CA). This is the ONLY Apple service in the whole activation/
install story that is NOT behind the FMI wall.

Agent internals (binary RE):
- identity lookup (`com.apple.lockdown.identity.activation`) is REQUIRED FIRST;
  without it the agent never constructs the request — "MIS: Could not find device identity"
  precedes "MIS: Failed to construct authorization request"
- the request is a CMS blob signed with the identity ("Could not create CMS blob")
- the response keys it reads: `com.apple.mis.ppq.load-time`, timeout — i.e. the server
  returns an authorization verdict + grace period

So a MITM (with the on-device debugging CA) can only ever help AFTER a valid identity
exists — it cannot substitute for one.

### 2. mobileactivationd import validation — anchor-verified, two-tier
`HandleActivationInfo` runs `SecTrustCreateWithCertificates` + `SecTrustSetAnchorCertificates`
+ `SecTrustEvaluate` with an "iphone activation policy". Failure path strings:
- "Failed to create Basic X509 policy" / "failed to create iphone activation policy"
- "Could not verify record with production certificates. Attempting factory certificates"
- "Failed to validate activation record / signature / response signature"
- "Failed to verify account token signature / activation record certificate / device certificates"

There is an `_allowInvalidCert` axis and a production->factory anchor fallback, but both
anchor sets are Apple-held keys embedded in the binary. A self-signed record cannot import:
the crafted-record idea (bind our own CA-signed cert to the device-held CSR key) dies at
SecTrustEvaluate — the cert must be minted by Apple production or Apple factory CAs.

lockdownd's own MAE-based Activate path links the same SecTrust anchor machinery, and
its legacy `ActivationPrivateKey/ActivationPublicKey` record fields are the ancient
Apple-ships-the-keypair format — also Apple-minted, same anchors.

### 3. The Sliver relay is a fully static template
POSTed fresh device ActivationInfo with three different AppleSerialNumber values:
- F6QTF059DFHW (real)
- F6QTF059DFHX (shifted)
- C02QWERTYUIOP (fictional)

All three → byte-identical response (same FairPlayKeyData/AccountToken/DeviceCertificate/
AccountTokenCertificate fingerprints). Combined with the earlier morning-vs-evening test
(fresh CSRs hours apart → identical bytes), the relay serves ONE canned record to all
requesters. It never mints, never forwards our CSR. There is no upstream FMI bypass to
study — there is no upstream at all.

Also: `com.apple.mobileactivationd.lockdown` is NOT offered by lockdownd on iOS 9.3.5
(InvalidServiceError live) — the 7-command XPC surface in the binary is the whole surface.

## Consequence — the minimal unlock-set

The identity `com.apple.lockdown.identity.activation` can only ever exist on this device
if Apple (production or factory CA) minted the DeviceCertificate. Apple issues it only
through the albert flow, which presents the previous owner's FMI lock (v•••••@gmail.com)
for this serial. Locally, every import path validates Apple anchors. Therefore the ONLY
things that change this device's fate:

1. the previous owner's Apple ID credentials (removes the lock / activates cleanly)
2. an enterprise distribution certificate (any org in Apple's Developer Program)
3. code execution via checkm8 — blocked on this Pop!_OS host by microsecond USB pacing;
   proven from macOS hosts (the pre-Arduino A5 era ipwndfu) — the borrowed-Mac path
4. hardware (Arduino A5 pwn — excluded by the no-hardware constraint)

## Working channels that remain

- App Store sign-in/browse/queue: works. Some store installs DO work (Thyme installed);
  the fpinit licensing path is flaky per-app on 32-bit, not universally dead.
  => systematic per-app trial of legacy 32-bit reader apps (Documents 5, Adobe Reader,
  Dropbox-era file managers) is the practical route for PDF/classwork needs.
- Books server http://192.168.0.15:8088 — unchanged, unaffected.
- Sideload installs remain blocked by the identity wall (proven again tonight with the
  correctly dual-hashed no-get-task-allow variant: same -25300).
