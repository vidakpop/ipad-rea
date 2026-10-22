#!/usr/bin/env python3
"""Decrypt an Apple IMG3 DATA payload using openssl (no pycryptodome needed).

usage: img3decrypt-ssl.py <in.img3> <out.bin> <iv-hex> <key-hex>

IMG3 layout (little-endian): 20-byte header, then tags. Each tag is
tag(4) + tag_total_len(4) + tag_data_len(4) + payload. The ATAD ("DATA")
tag's ciphertext is (tag_total_len - 12) bytes, AES-256-CBC; the true
plaintext size is tag_data_len (truncate after decryption).

IV/Key come from The Apple Wiki firmware-keys pages, e.g.
Keys:Genoa 13G36 (iPad2,1) for the iPad 2's iOS 9.3.5 files.
"""
import os
import struct
import subprocess
import sys
import tempfile


def parse_img3(data: bytes):
    magic, _total_len, _data_len = struct.unpack_from("<4sII", data, 0)
    if magic != b"3gmI":
        raise SystemExit(f"not an IMG3 file (got {magic!r})")
    off = 20
    while off < len(data):
        tag, tag_total_len, tag_data_len = struct.unpack_from("<4sII", data, off)
        if tag == b"ATAD":
            cipher_len = tag_total_len - 12
            if cipher_len % 16 != 0:
                raise SystemExit(f"ciphertext len {cipher_len} not block-aligned")
            return data[off + 12 : off + 12 + cipher_len], tag_data_len
        off += tag_total_len
    raise SystemExit("no DATA tag found")


def main() -> int:
    if len(sys.argv) != 5:
        print(f"usage: {sys.argv[0]} <in.img3> <out.bin> <iv-hex> <key-hex>",
              file=sys.stderr)
        return 2
    infile, outfile, iv_hex, key_hex = sys.argv[1:]
    cipher, plain_len = parse_img3(open(infile, "rb").read())
    with tempfile.NamedTemporaryFile(delete=False) as cf:
        cf.write(cipher)
        cpath = cf.name
    ppath = cpath + ".plain"
    subprocess.run(
        ["openssl", "enc", "-d", "-aes-256-cbc", "-K", key_hex, "-iv", iv_hex,
         "-nopad", "-in", cpath, "-out", ppath],
        check=True,
    )
    plain = open(ppath, "rb").read()[:plain_len]
    open(outfile, "wb").write(plain)
    os.unlink(cpath)
    os.unlink(ppath)
    print(f"wrote {len(plain)} bytes to {outfile} "
          f"(ciphertext was {len(cipher)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
