#!/usr/bin/env python3
"""
install-localprovisioned.py — probe installd's InstallLocalProvisioned SPI.

iOS 9 installd options chain (from RE of 13G36 binaries):
    InstallForLaunchServices / VerifyForMigrator / InstallForDataMigrator /
    AllowInstallLocalProvisioned / InstallLocalProvisioned / SkipBlacklist
and -[MIInstallableBundle _validateBundle:...performingOnlineAuthorization:
verifyingForMigrator:allowingFreeProfileValidation:error:] shows the online-auth
step is PARAMETRIC. This probe smuggles the LocalProvisioned flags through
installation_proxy ClientOptions and watches what installd does.

Usage:
    tools/install-localprovisioned.py <ipa> [variant]
variants:
    dev          -> {"PackageType": "Developer"}
    local        -> {"PackageType": "Developer", "InstallLocalProvisioned": True}
    local2       -> {"InstallLocalProvisioned": True, "AllowInstallLocalProvisioned": True, "SkipBlacklist": True}
    migrator     -> {"PackageType": "Developer", "VerifyForMigrator": True}   # the failed-verification-forgiveness path
"""
import asyncio
import sys
from pathlib import Path

UDID = "ae85db46b1dd7faa563fc6eb53780515a67dfcc7"

VARIANTS = {
    "dev":      {"PackageType": "Developer"},
    "local":    {"PackageType": "Developer", "InstallLocalProvisioned": True},
    "local2":   {"InstallLocalProvisioned": True, "AllowInstallLocalProvisioned": True, "SkipBlacklist": True},
    "migrator": {"PackageType": "Developer", "VerifyForMigrator": True},
}


async def main() -> None:
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    ipa = Path(sys.argv[1])
    variant = sys.argv[2] if len(sys.argv) > 2 else "local"
    options = VARIANTS.get(variant)
    if options is None:
        sys.exit(f"unknown variant {variant}; pick one of {list(VARIANTS)}")

    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.installation_proxy import InstallationProxyService

    lockdown = await create_using_usbmux(serial=UDID)
    print(f"connected: {lockdown.udid} iOS {lockdown.product_version}")
    print(f"variant {variant}: ClientOptions = {options}")

    async with InstallationProxyService(lockdown) as installation:
        try:
            await installation.install_from_local(ipa, cmd="Install", options=dict(options))
            print("RESULT: installation reported Complete")
        except Exception as e:
            print(f"RESULT: failed -> {e}")


asyncio.run(main())
