# Genuine device activation attempt — Nov 11, final answer

## What was tested (all on-device, software-only)

1. **lockdownd 9.3.5 contains the full genuine activation protocol**
   (verified in the decrypted binary): `create_activation_info`,
   `ActivationPrivateKey/PublicKey`, `handle_activate`, `MAEGate_HandleActivate`,
   `com.apple.lockdown.identity.activation` — AND it is reachable:
   `lockdown GetValue ActivationInfo` returns a FRESH device-generated
   ActivationInfoXML (own keypair + CSR, `DeviceCertRequest`) even while
   hacktivated.
2. **deactivate() works** — FactoryActivated → Unactivated cleanly.
3. **Direct to albert.apple.com with our fresh device CSR**:
   Apple responds `application/x-buddyml` — the **Activation Lock login
   page** (12 KB form, title "Activation Lock") — the FMI wall. Only the
   lock-owning Apple ID (previous owner) can pass it.
4. **Via the Sliver relay (cengdealajr.gearhostpreview.com/sliver.php)**:
   returns an Apple-signed activation record with OUR fresh ActivationRandomness
   (2D4E1E72-9818…) — BUT the FairPlayKeyData bytes are byte-identical to
   this morning's act.sh response = **the relay serves a cached/template
   record, NOT one bound to our device's fresh keypair.** On-device
   `handleActivationInfo` accepts it (state→FactoryActivated) but the
   system-keychain identity never materializes; after reboot the state
   falls back to Unactivated.
5. **Online-auth-agent still reports -25300** (no device identity) after
   every genuine-processed variant — binary-proven: free-profile app
   installs stay impossible.

## Conclusion (final, evidenced)

The missing activation identity for free-profile app installs can only be
created by a **genuine Apple response bound to this device's live CSR** —
and Apple only issues that through the **Activation Lock gate**
(previous-owner credentials). The Sliver hacktivation family cannot
ever produce it (server-side cached records). This closes the last
software-only activation loophole for FMI'd devices:
- activation → blocked by owner-credential crypto at Apple
- enterprise trust → blocked by enterprise-account requirement
- identity in keychain → root-only, needs one of the above first

Remaining levers unchanged: checkm8 (hardware-timed host), or research
grade chains (Safari/parser bugs).

## Artifacts
- /tmp/activation-buddyml.html — Apple's lock form (set of server fields)
- /tmp/activation-response.xml morning record for reference
- tools/genuine-activate.py — the full on-device genuine flow driver
