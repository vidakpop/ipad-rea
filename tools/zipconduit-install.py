#!/usr/bin/env python3
"""
zipconduit-install.py — install an (unsigned) .app on the iPad via
com.apple.streaming_zip_conduit, the way Xcode streams apps to a device.

Why: on iOS 9 the conduit's extractor creates every file 0644 and ignores the
zip mode metadata, so extraction alone cannot produce an executable.  But when
InstallTransferredDirectory is set, the device then installs the transferred
package with installation_proxy, and the install step marks the package's main
executable (CFBundleExecutable) 0755.  So an .app whose main executable is
kloader lands kloader as a 0755 binary inside its bundle container — which
debugserver can then launch as root (see tools/debugserver-launch.py).

This is also a jailbreak test: installing an unsigned app only succeeds when
amfi is patched, i.e. when the (semi-tethered) jailbreak is active.

Usage:
    /tmp/p3venv/bin/python tools/zipconduit-install.py <path/to/App.app>

Requires: pip install pymobiledevice3 (see docs/k93-boot-linux.md).
"""
import asyncio
import sys
from pathlib import Path

UDID = "ae85db46b1dd7faa563fc6eb53780515a67dfcc7"


async def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    app = Path(sys.argv[1])
    if not (app / "Info.plist").is_file():
        sys.exit(f"error: {app} does not look like an .app (no Info.plist)")

    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.streaming_zip_conduit import StreamingZipConduitService

    lockdown = await create_using_usbmux(serial=UDID)
    print(f"connected: {lockdown.udid}  iOS {lockdown.product_version}")
    async with StreamingZipConduitService(lockdown) as service:
        await service.install(
            app,
            developer=True,
            handler=lambda p: print(f"progress: {p}%"),
        )
    print(f"installed: {app.name}")


asyncio.run(main())
