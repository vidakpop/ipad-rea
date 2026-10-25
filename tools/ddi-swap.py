#!/usr/bin/env python3
"""
ddi-swap.py — swap the mounted Developer Disk Image for a (modified) one.

The iPad allows only one Developer image mounted at a time; ideviceimagemounter
fails with a bare "ImageMountFailed" in that case, which says nothing about
whether the new image itself was accepted.  This tool uses pymobiledevice3's
image mounter to unmount first (if the device supports UnmountImage), then
uploads and mounts the given image with the given signature, printing the
device's detailed error when the mount is refused.  If the new image is
refused and a fallback image is given, the fallback is mounted instead so the
device is never left without a Developer Disk Image (debugserver lives in it).

Usage:
    tools/ddi-swap.py <new-image.dmg> <new-image.signature> \
                      [fallback-image.dmg fallback-signature]

Example:
    tools/ddi-swap.py build/ddi/kdfu-ddi.dmg build/ddi/DeveloperDiskImage.dmg.signature \
                      build/ddi/DeveloperDiskImage.dmg build/ddi/DeveloperDiskImage.dmg.signature
"""
import asyncio
import sys

from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.mobile_image_mounter import MobileImageMounterService


async def mount(svc, image_path, sig_path):
    image = open(image_path, "rb").read()
    sig = open(sig_path, "rb").read()
    await svc.upload_image("Developer", image, sig)
    print(f"uploaded {image_path} ({len(image)} bytes)")
    await svc.mount_image("Developer", sig)
    print(f"MOUNTED {image_path}")


async def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    new_img, new_sig = sys.argv[1], sys.argv[2]
    fallback = sys.argv[3:5] if len(sys.argv) >= 5 else None

    lockdown = await create_using_usbmux()
    svc = MobileImageMounterService(lockdown)
    print(f"Developer image mounted: {await svc.is_image_mounted('Developer')}")
    if await svc.is_image_mounted("Developer"):
        try:
            await svc.unmount_image("/Developer")
            print("unmounted /Developer")
        except Exception as e:
            print(f"unmount failed: {type(e).__name__}: {e}")
            sys.exit("cannot unmount on this iOS; reboot the device and re-run")

    try:
        await mount(svc, new_img, new_sig)
    except Exception as e:
        print(f"MOUNT REFUSED: {type(e).__name__}: {e}")
        if fallback:
            print("falling back to the original image")
            await mount(svc, fallback[0], fallback[1])
        else:
            sys.exit(1)
    print(f"Developer image mounted now: {await svc.is_image_mounted('Developer')}")


asyncio.run(main())
