#!/usr/bin/env python3
"""
genuine-activate.py — perform the REAL activation handshake on this iPad 2.

act.sh (Sliver) only ever wrote a canned activation record into lockdownd's
files. It never ran the device-side protocol, so the activation identity
(com.apple.lockdown.identity.activation in the system keychain) was never
created — which is why every app install dies at online-auth (errSecItemNotFound
in online-auth-agent).

This drives the genuine flow end-to-end:
  1. lockdown Deactivate            (clears the hacktivation record)
  2. lockdown GetValue ActivationInfo   (device generates its OWN keypair + CSR)
  3. POST to albert.apple.com      (the same request shape act.sh's relay uses)
  4. lockdown Activate             (device processes + imports the identity)
  5. ActivationStateAcknowledged

If Apple answers with a credentials form (buddyml), the tool prompts for them
inline — enter the user's Apple ID + app-specific password there.

Safety: if anything fails we just re-run act.sh to restore hacktivation.
"""
import asyncio
import sys

UDID = "ae85db46b1dd7faa563fc6eb53780515a67dfcc7"


async def main() -> None:
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.mobile_activation import MobileActivationService

    lockdown = await create_using_usbmux(serial=UDID)
    ma = MobileActivationService(lockdown)
    print("== connected, iOS", lockdown.product_version)
    print("== current activation state:", await ma.state())

    for step in range(2):
        answer = input(f"\n[step {step+1}] state={await ma.state()} — proceed? (y/N): ")
        if answer.strip().lower() != "y":
            print("aborted, no changes made")
            return
        if step == 0:
            print("== deactivate()")
            try:
                r = await ma.deactivate()
                print("   deactivate response:", r)
            except Exception as e:
                print("   deactivate error (continuing):", e)
        else:
            print("== activate() — genuine handshake with device + Apple")
            try:
                await ma.activate()
                print("   ACTIVATION RESULT: success")
            except Exception as e:
                print("   ACTIVATION RESULT: failed ->", e)
        print("== state now:", await ma.state())

    print("\nIf the last state is Activated: run the EverPwnage install retry next.")
    print("If anything else: re-run act.sh to restore hacktivation.")


asyncio.run(main())
