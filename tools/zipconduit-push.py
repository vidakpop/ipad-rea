#!/usr/bin/env python3
"""
zipconduit-push.py — land EXECUTABLE files on the iPad via com.apple.streaming_zip_conduit.

This solves the "+x problem": jailed AFC creates files 0644 and its chmod is
ENOSYS, and there is no ssh/afc2/Cydia.  streaming_zip_conduit is a stock
lockdown service (no jailbreak needed to TALK to it) that extracts a streamed
headerless ZIP into /var/mobile/Media/<MediaSubdir>/.

The mode story, measured on iOS 9.3.5: the extractor applies the metadata
plist's StandardFilePerms/StandardDirectoryPerms to every entry and ignores
the per-entry "SZ" extra field (a newer-iOS feature).  So we send our own
metadata with StandardFilePerms = 0755 and every file lands executable.

Protocol reference: pymobiledevice3's StreamingZipConduitService
(doronz88/pymobiledevice3, services/streaming_zip_conduit.py).

Usage:
    python3 -m venv /tmp/p3venv && /tmp/p3venv/bin/pip install pymobiledevice3
    /tmp/p3venv/bin/python tools/zipconduit-push.py <dest-subdir> <file> [file ...]

Example (stage kloader + patched iBSS with exec bits):
    /tmp/p3venv/bin/python tools/zipconduit-push.py PublicStaging/kdfu \\
        build/tools/kloader build/adt-k93ap/iBSS.k93.patched

The files then appear at /var/mobile/Media/<dest-subdir>/ with mode 0755 (check
with the jailed AFC mount, e.g. ls -la /tmp/ipad-media/PublicStaging/kdfu/).
"""
import asyncio
import plistlib
import stat
import sys
from pathlib import Path

UDID = "ae85db46b1dd7faa563fc6eb53780515a67dfcc7"

ZIP_METADATA_PATH = "META-INF/com.apple.ZipMetadata.plist"
CENTRAL_DIRECTORY_SIGNATURE = b"PK\x01\x02"
STANDARD_DIRECTORY_MODE = stat.S_IFDIR | 0o755
STANDARD_FILE_MODE = stat.S_IFREG | 0o755  # executables: this is the whole point


async def main() -> None:
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    dest = sys.argv[1].strip("/")
    files = [Path(p) for p in sys.argv[2:]]

    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.streaming_zip_conduit import (
        StreamingZipConduitService,
        _bytes_entry,
        _directory_entry,
    )

    entries = [_bytes_entry(p.name, STANDARD_FILE_MODE, p.read_bytes()) for p in files]
    for p in files:
        print(f"entry: {p.name}  mode=0755  {p.stat().st_size} bytes")

    # Metadata record that opens the stream; StandardFilePerms is applied to
    # every extracted file on iOS 9 (the per-entry SZ extra field is ignored).
    metadata = plistlib.dumps({
        "RecordCount": len(entries) + 2,
        "StandardDirectoryPerms": STANDARD_DIRECTORY_MODE,
        "StandardFilePerms": STANDARD_FILE_MODE,
        "TotalUncompressedBytes": sum(e.size for e in entries),
        "Version": 2,
    })
    stream_entries = [
        _directory_entry("META-INF"),
        _bytes_entry(ZIP_METADATA_PATH, stat.S_IFREG | 0o644, metadata),
        *entries,
    ]

    setup = {
        "InstallOptionsDictionary": {"PackageType": "Developer"},
        # False = extract only, do not try to install the result as an app.
        "InstallTransferredDirectory": False,
        "MediaSubdir": dest,
        "UserInitiatedTransfer": False,
    }

    lockdown = await create_using_usbmux(serial=UDID)
    print(f"connected: {lockdown.udid}  iOS {lockdown.product_version}")
    async with StreamingZipConduitService(lockdown) as service:
        await service.service.send_plist(setup)
        for entry in stream_entries:
            await service.service.sendall(entry.header())
            for chunk in entry.chunks():
                await service.service.sendall(chunk)
        await service.service.sendall(CENTRAL_DIRECTORY_SIGNATURE)

        while True:
            response = await service.service.recv_plist()
            print(f"device: {response}")
            if "Error" in response:
                sys.exit(f"error: device refused the transfer: {response['Error']}")
            if response.get("Status") == "DataComplete":
                break
    print(f"transfer complete -> /var/mobile/Media/{dest}/ (mode 0755)")


asyncio.run(main())
