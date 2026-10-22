#!/usr/bin/env python3
"""List a directory inside an IPSW's root filesystem (k93 helper).

    rootfs-list-k93.py IPSW DMG KEY DIR [DIR ...]

Reuses the encrcdsa/UDIF/HFS+ readers from rootfs-extract-cryptography.py.
Prints one line per entry: kind, size (files), name.  Used to locate the
multitouch props and the BCM4330 Wi-Fi TRX/NVRAM under /usr/share/firmware.
"""
import importlib.util
import os
import shutil
import struct
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "rex", os.path.join(HERE, "rootfs-extract-cryptography.py")
)
rex = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rex)


def _catalog(hfs):
    """(parent_cnid, name) -> (kind, cnid, size) for every catalog record."""
    out = {}
    for node, o in hfs.leaves(hfs.catalog):
        klen = rex.u16(node, o)
        nlen = rex.u16(node, o + 6)
        name = node[o + 8 : o + 8 + 2 * nlen].decode("utf-16-be")
        rec = node[o + 2 + klen : o + 2 + klen + 248]
        kind = struct.unpack_from(">h", rec, 0)[0]
        if kind not in (1, 2):  # skip thread records (3/4): key only, no data
            continue
        cnid = rex.u32(rec, 8)
        size = rex.u64(rec, 88)  # data fork logical size
        out[(rex.u32(node, o + 2), name)] = (kind, cnid, size)
    return out


def resolve_dir(cat, path):
    parent = 2  # kHFSRootFolderID
    for name in [p for p in path.split("/") if p]:
        rec = cat.get((parent, name))
        if rec is None:
            rex.fail("%s: no '%s'" % (path, name))
        kind, cnid, _ = rec
        if kind != 1:
            rex.fail("%s: '%s' is not a folder" % (path, name))
        parent = cnid
    return parent


def main():
    if len(sys.argv) < 5:
        sys.exit(__doc__)
    ipsw, dmg, keyhex = sys.argv[1:4]
    dirs = sys.argv[4:]
    key = bytes.fromhex(keyhex)
    tmp = os.path.join(HERE, "..", "build", "fw-k93", ".list.dmg.tmp")
    os.makedirs(os.path.dirname(tmp), exist_ok=True)
    try:
        with zipfile.ZipFile(ipsw) as z, z.open(dmg) as src, open(tmp, "wb") as dst:
            shutil.copyfileobj(src, dst, 1 << 20)
        with open(tmp, "rb") as f:
            src = rex.Encrcdsa(f, key) if f.read(8) == b"encrcdsa" else rex.Plain(f)
            hfs = rex.Hfs(rex.Udif(src))
            cat = _catalog(hfs)
            for d in dirs:
                cnid = resolve_dir(cat, d)
                print("%s:" % d)
                for (parent, name), (kind, ecnid, size) in sorted(
                    cat.items(), key=lambda kv: kv[0][1]
                ):
                    if parent != cnid:
                        continue
                    print("  %-4s %10d  %s" % ("dir" if kind == 1 else "file", size, name))
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


if __name__ == "__main__":
    main()
