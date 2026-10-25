#!/usr/bin/env python3
"""
mbdb-add.py — add or re-mode file records inside an idevicebackup2 backup.

Why this exists: the stock backup agent never sees the files we drop into
/var/mobile/Media (AFC / streaming_zip_conduit), so a plain backup/restore
cannot change their mode — they are simply absent from Manifest.mbdb.  But
the restore is driven entirely by that manifest: append a record with the
mode we want, place the file's bytes in the backup folder under the right
file id (sha1 of "<domain>-<path>"), and the restore recreates the file on
the device with that mode (if backupd honors the mode field — measured, see
docs/k93-no-cydia-toolbox.md).

Record layout (mbdb v5, big endian), reverse engineered and cross-checked
against pyiosbackup's construct parser and idevicebackup2's own listing:

    u16 domain_len, domain, u16 path_len, path, u16 link_len, linktarget,
    u16 hash_len, data_hash, u16 key_len, encryption_key,
    u16 mode, u32 inode, u32 unknown, u32 uid, u32 gid,
    u32 mtime, u32 atime, u32 ctime, u64 size, u8 flags, u8 nprops, props...

Empty length-prefixed fields are the sentinel 0xffff.  The trailing "flags"
byte is the data-protection class (4 = NSFileProtectionNone, the value used
by ordinary HomeDomain files; 0 for directories).

Usage:
    tools/mbdb-add.py <backup-dir> add <domain> <path> <octal-mode> [local-file]

    add      if a record for <domain>/<path> already exists, patch its mode in
             place; otherwise append a new record.  With <local-file> the
             record is a regular file and the bytes are copied into the backup
             under their file id; without it the record is a directory.

Example (make kloader executable on the device via a restore):

    tools/mbdb-add.py build/mb-test add HomeDomain Media/kdfu 040755
    tools/mbdb-add.py build/mb-test add HomeDomain Media/kdfu/kloader 0100755 build/tools/kloader
    tools/mbdb-add.py build/mb-test add HomeDomain Media/kdfu/pwnediBSS 0100644 build/tools/pwnediBSS
    idevicebackup2 restore build/mb-test --no-reboot --skip-apps
"""
import hashlib
import os
import struct
import sys
import time

FILE_FLAGS = 4   # data-protection class: NSFileProtectionNone
DIR_FLAGS = 0


def parse_records(data):
    """Parse an mbdb file into a list of record dicts (with byte offsets)."""
    if bytes(data[:6]) != b"mbdb\x05\x00":
        raise SystemExit("error: not an mbdb v5 file")
    off, n = 6, len(data)
    out = []

    def rds(off):
        (l,) = struct.unpack_from(">H", data, off)
        if l == 0xFFFF:
            return b"", off + 2
        return bytes(data[off + 2:off + 2 + l]), off + 2 + l

    while off < n:
        start = off
        domain, off = rds(off)
        path, off = rds(off)
        _link, off = rds(off)
        (hl,) = struct.unpack_from(">H", data, off)
        off += 2 + (0 if hl == 0xFFFF else hl)
        (kl,) = struct.unpack_from(">H", data, off)
        off += 2 + (0 if kl == 0xFFFF else kl)
        mode_off = off
        (mode,) = struct.unpack_from(">H", data, off)
        off += 2
        off += 16  # inode, unknown, uid, gid
        off += 12  # mtime, atime, ctime
        (size,) = struct.unpack_from(">Q", data, off)
        off += 8
        flags = data[off]
        off += 1
        (nprops,) = struct.unpack_from(">B", data, off)
        off += 1
        for _ in range(nprops):
            _, off = rds(off)
            _, off = rds(off)
        out.append(dict(start=start, end=off, domain=domain, path=path,
                        mode=mode, mode_off=mode_off, size=size, flags=flags))
    return out


def enc_str(b):
    b = b.encode() if isinstance(b, str) else b
    return struct.pack(">H", len(b)) + b if b else b"\xff\xff"


def build_record(domain, path, mode, size, flags, uid=501, gid=501):
    now = int(time.time())
    r = enc_str(domain) + enc_str(path) + enc_str(b"") + enc_str(b"") + enc_str(b"")
    r += struct.pack(">H", mode)
    r += struct.pack(">IIII", 0, 0, uid, gid)      # inode, unknown, uid, gid
    r += struct.pack(">III", now, now, now)       # mtime, atime, ctime
    r += struct.pack(">Q", size)
    r += struct.pack(">BB", flags, 0)             # flags, no properties
    return r


def file_id(domain, path):
    return hashlib.sha1(f"{domain}-{path}".encode()).hexdigest()


def main():
    if len(sys.argv) < 5 or sys.argv[2] != "add":
        sys.exit(__doc__)
    backup, _, domain, path, mode_s = sys.argv[1:6]
    local = sys.argv[6] if len(sys.argv) > 6 else None
    mode = int(mode_s, 8)

    udid_dir = next(d for d in os.listdir(backup)
                    if os.path.isdir(os.path.join(backup, d)))
    mbdb_path = os.path.join(backup, udid_dir, "Manifest.mbdb")
    data = bytearray(open(mbdb_path, "rb").read())
    recs = parse_records(data)

    existing = next((r for r in recs
                     if r["domain"] == domain.encode() and r["path"] == path.encode()), None)
    if existing:
        struct.pack_into(">H", data, existing["mode_off"], mode)
        open(mbdb_path, "wb").write(bytes(data))
        print(f"patched record: {domain}/{path} mode {existing['mode']:o} -> {mode:o}")
        return

    blob = b""
    if local:
        blob = open(local, "rb").read()
        with open(os.path.join(backup, udid_dir, file_id(domain, path)), "wb") as f:
            f.write(blob)
    rec = build_record(domain, path, mode, len(blob), FILE_FLAGS if local else DIR_FLAGS)
    data += rec
    open(mbdb_path, "wb").write(bytes(data))
    kind = "file" if local else "dir"
    print(f"appended {kind} record: {domain}/{path} mode={mode:o} "
          f"size={len(blob)} file_id={file_id(domain, path)}")


main()
