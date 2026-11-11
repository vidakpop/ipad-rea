# Reboot permanence — mechanism fully proven (Nov 11, end of night)

## Live experiment
Two reboots of the hacktivated (act.sh/relay, FactoryActivated) iPad 2:

| Event | State before | State after boot | Recovery |
|---|---|---|---|
| Reboot 1 (22:31) | FactoryActivated | **Unactivated** (stable, 2+ min) | act.sh |
| Reboot 2 (22:39) | FactoryActivated | **Unactivated** (stable, 2+ min) | act.sh |

## Boot-time capture (the mechanism, exact daemons + codes)

```
22:39:16 identityservicesd: WiFi is associated YES
22:39:24 identityservicesd: No identity found!
22:39:24 identityservicesd: [Warning]   Identity Problem
22:39:24 identityservicesd: [Warning]     Lockdown identity cert 0x0   (err: -25300)
22:39:24 identityservicesd: [Warning]     APS identity cert 0x0         (err: -25300)
22:39:24 identityservicesd: [Warning] Re-certifying device (in background)
22:39:24 mobileactivationd:  Recertification (SB) requested by identityservicesd<45>
22:39:27 identityservicesd: [Warning] Device re-certified: NO
```

And at apply time (act.sh), for contrast:

```
22:36:27 mobileactivationd: MA: -[MobileActivationDaemon handleActivationInfo:withCompletionBlock:]: Activation requested by lockdownd<30>
```

## What this proves

1. **Activation state is recomputed at boot from the identity's presence.** act.sh's
   apply sets lockdown's *state display* (FactoryActivated) successfully, but the
   identity import that mobileactivationd's `handleActivationInfo` should perform
   fails silently (record cert/key mismatch → anchored validation, per round-3 RE).
2. **The device itself retries the identity at every boot** (identityservicesd
   "Recertification (SB)" via mobileactivationd) and fails: `Device re-certified: NO`.
   The re-certification path would need the Apple-anchored record for the *current*
   device keypair — i.e. an albert mint — which is FMI-gated by the previous owner.
3. Therefore: **reboot permanence and app installs are the same missing artifact** —
   the `com.apple.lockdown.identity.activation` identity. No amount of re-hackactivating,
   record copying, profile installing, or store activity creates it.

## The complete, final route map for THIS device

| Goal | What it requires | Status |
|---|---|---|
| Reboot-proof activation | Previous owner's 'v•••••@gmail.com' creds (removes FMI, real albert mint) | unobtainable |
| App installs (sideload) | Same identity, or enterprise cert, or exec | blocked |
| Store app installs | Per-app trial (Thyme installed!) | partially working |
| Boot-patched permanent state (EverPwnage etc.) | checkm8 code exec first | hardware-timed gate |
| Linux | checkm8 → patched iBSS/iBEC → kernel | ready in repo once pwned |

Everything is in the repo: k93 boot-chain analysis, iBEC autogo patches, the checkm8
host port, payload builders, Linux boot docs. The software side is complete; the gate
that remains open is a host that can emit exploit USB timing (a Mac) or the owner's
credentials.

## Practical carries for the user meanwhile

- Books/PDF channel via the local HTTP server (unchanged).
- Store trials: Documents 5 / Adobe Reader / Dropbox-class legacy apps may install
  like Thyme did — per-app licensing is flaky, not universally dead.
- iPad usable state: kept at FactoryActivated via act.sh after any reboot.

## Post-script: the "semitethered" assumption resolved (same night)

The user's semitethered state was long treated as possible live code execution. The
repo's own jailbreak probe (tools/zipconduit-install.py with build/fakeapp/Kdfu.app,
unsigned) settles it:

```
ApplicationVerificationFailed: 0xe800801c (No code signature found.)
```

Per boot/enter-kdfu-nossy.sh: "the iPad looks STOCK — the install was rejected at
signature verification." The user's semitethered is Sliver's hacktivation (act.sh
re-run after reboot), not a jailbreak. No code execution exists on this device.
The kdfu→Linux chain remains fully built and waiting on a boot-chain exploit
(checkm8 via macOS host, or hardware).
