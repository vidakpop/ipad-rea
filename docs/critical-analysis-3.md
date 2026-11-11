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

## Round 4 — checkm8 USB physics, measured live (Nov 11/12 night)

### Native (axi0mX host) flow refuted on 838.3 by direct test
- req_stall (CLEAR_FEATURE EP 0x80) → device STALLs as expected
- then EVERY sync descriptor leak (GET_DESCRIPTOR string, wLength 0x80) HANGS:
  no data, no stall, 500ms timeouts. With or without the preceding req_stall.
- The hang is not a malfunction — it IS checkm8's premise on this ROM: the
  838.3 USB-task keeps the request pending (allocation retained) instead of
  completing. The 1458.2 (4S) flow that works from laptops relies on the device
  completing transfers; 838.3 never completes IN responses on its own.
- Consequence: **no plain-control-transfer host flow (Linux, macOS, or Windows)
  can drive stage 1 on iBoot-838.3.** The Arduino's per-packet manual dispatching
  is not a convenience — it is the only way to walk the 838.3 state machine.

### Pacing curve (sketch mode, live)
| cancel deadline | delivered | outcome |
|---|---|---|
| 400 µs  | 0x100 (4 pkts)  | pending, incomplete |
| 1.1 ms  | 0x140 (5 pkts)  | pending, incomplete |
| 9 ms    | 0x700 then COMPLETED at 9.1 ms | end_of_transfer fires; global state reset |

The 0x700 data stage takes ~8.8 ms on this controller, and the status phase is
hardware-scheduled immediately behind the last data packet — usbfs has no
cancel window between them. The sketch mode's "remainder transfer" already
lands the device at rcvd=padding of length=padding+0x40 with no status (the
knife-edge state), and stage 3 still dies identically — so the remaining
defect is in stage 3 fidelity: the critical-IN (setup + one IN packet, abort
mid-data) leaves the 0x81 request's io_request armed on the Arduino — that
armed request is what the overwrite's invalid (0x00,0x00) SETUP writes into.
A kernel-managed critical-IN that never receives data never arms it.

### Corrections to earlier conclusions
1. sync descriptor requests COMPLETED observable data (actual=0x100...) on OUT,
   but IN responses hang — the port's in-cancel feng shui was the only working
   stage-1 shape all along.
2. "Borrow a Mac" does NOT open this device's DFU: the hang is device-side.
   macOS libusb would hit the identical wall. (The Mac helps OTHER cpids, not
   838.3.)
3. The bus reset before stage 1 wedges a fresh DFU entry about half the time —
   use --init-resets 0.

### What remains, ranked
1. build/src/checkm8-a5-pico (in this repo): a $4 Raspberry Pi Pico dongle,
   no soldering, plugs into the laptop, runs the proven 838.3 sequence raw.
   This is the only remaining route to pwned DFU on this iPad.
2. Continued stage-3 fidelity RE against iBoot-838.3's SETUP-in-data state
   machine (needs a USB packet analyzer or deterministic emulator — software-
   only, but a project, not a tweak).
3. Everything else tonight: closed with signed verdicts.

## Round 5 — the primitive identified: overhang packets (end of night)

Artifact provenance audit (settled):
- the vanilla a1exdandy sketch's `#define A5_8942` is just its clone's last config; its
  constants.h carries both blocks; our port uses the A5_8940 block (padding 0x6C0,
  payload 704B sha1 63ddb...) — CORRECT for iPad 2,1 / S5L8940X
- LukeZGD's A5_8940 payload (640B) is carried as --payload luke; never yet tried on
  device; the shared overwrite (64B b9fe...) is common lineage
- ipwndfu-rewrite-c (checkm8_libusb): A10-only, stock libusb, no A5 value

THE primitive, understood: the sketch's set_global_state sends SETUP(wLength=0x40)
followed by TWO 0x40 OUT packets. The 838.3 DFU reader has no length check, so the
second packet is ingested past the declared length — that overhang corrupts the
global USB state (the exploit's engine). Observed live tonight: usbfs delivers
exactly wLength and censors the overhang (actual=64 on our 0x80-data submission).
xHCI/EHCI enforce wLength at the hardware TD level — so ANY kernel-managed host
stack (Linux/macOS/Windows, libusb or not) cannot emit the primitive.

Software-only paths that remain (ranked, honest):
1. Custom Linux kernel module driving the xHC transfer rings directly: hand-built
   TD chains can emit SETUP + over-length data + no-status at uframe precision.
   Real project (days), zero hardware, this laptop. The only remaining pure-software
   route to pwned DFU on iBoot-838.3.
2. --payload luke variant attempt (cheap; stage-3 death precedes payload use, so
   unlikely to matter until stage-3 landing is fixed).
3. The $4 Pi Pico (build/src/checkm8-a5-pico) — minutes, proven, but hardware.
