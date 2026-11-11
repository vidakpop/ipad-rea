#!/usr/bin/env python3
"""
install-probe2.py — empirically map installation_proxy ClientOptions keys to
installd's mobileinstall SPI selection. installd's NotEntitled error names the
demanded SPI, so each combo's verdict reveals the options->SPI table.

For each combo below, prints: combo -> {ProxyError (SPI demanded) | verification result}
"""
import asyncio
import sys
import traceback
from pathlib import Path

UDID = "ae85db46b1dd7faa563fc6eb53780515a67dfcc7"

COMBOS = [
    ("bare-local",        {"InstallLocalProvisioned": True}),
    ("bare-allow",       {"AllowInstallLocalProvisioned": True}),
    ("bare-migrator",    {"VerifyForMigrator": True}),
    ("user-local",       {"PackageType": "User", "InstallLocalProvisioned": True}),
    ("dev-LS",           {"PackageType": "Developer", "InstallForLaunchServices": True}),
    ("dev-migrator-key", {"PackageType": "Developer", "InstallForDataMigrator": True}),
    ("dev-skip-black",   {"PackageType": "Developer", "SkipBlacklist": True}),
]
IPA = sys.argv[1] if len(sys.argv) > 1 else "/tmp/evp/EverPwnage-signed.ipa"


async def main() -> None:
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.installation_proxy import InstallationProxyService

    ipa = Path(IPA)
    lockdown = await create_using_usbmux(serial=UDID)
    print(f"connected: {lockdown.udid} iOS {lockdown.product_version}")

    for name, options in COMBOS:
        print(f"\n===== {name}: {options}")
        try:
            async with InstallationProxyService(lockdown) as installation:
                try:
                    await installation.install_from_local(ipa, cmd="Install", options=dict(options))
                    print("  VERDICT: COMPLETE (installed!)")
                except Exception as e:
                    print(f"  VERDICT: {str(e)[:220]}")
        except Exception as outer:
            print(f"  OUTER-ERR: {outer}")


asyncio.run(main())
