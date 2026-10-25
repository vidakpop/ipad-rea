#!/usr/bin/env python3
"""Diagnostic: replicate plumesign's Apple SRP login (gsa.apple.com GsService2)
using LOCAL anisette data from Anisette.py (build/venv).

Purpose: tell apart "the app-specific password in .env is wrong" from
"the sideload tool's SRP/anisette is broken". Prints Apple's raw response.

Never prints the password. Reads APPLE_ID / APPLE_APP_PASSWORD from .env only.

Usage:  build/venv/bin/python tools/srp-login-test.py
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac as _hmac
import os
import plistlib
import secrets
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ANI_DIR = REPO / "build" / "anisette-config" / "anisette-py"
LIBS = ANI_DIR / "libs.bin"
PROV = ANI_DIR / "default.prov"

GSA = "https://gsa.apple.com/grandslam/GsService2"

# RFC 5054 2048-bit group (same as plumesign's srp::groups::G2048)
N = int(
    "ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050"
    "a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50"
    "e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b8"
    "55f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773bc"
    "a97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f8774854"
    "4523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6af8"
    "74e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb694b5"
    "c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73",
    16,
)
G = 2
NLEN = 256  # bytes


def _pad(b: bytes) -> bytes:
    return b.rjust(NLEN, b"\x00")


def _trim(i: int) -> bytes:
    return i.to_bytes(max(1, (i.bit_length() + 7) // 8), "big")


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for line in (REPO / ".env").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()
    return env


def anisette_headers() -> dict[str, str]:
    os.environ["XDG_CONFIG_HOME"] = str(REPO / "build" / "anisette-config")
    from anisette import Anisette  # type: ignore

    ani = Anisette.load(str(LIBS), str(PROV))
    data = dict(ani.get_data())
    ani.save_provisioning(str(PROV))

    headers: dict[str, str] = {}
    for k, v in data.items():
        # match plumesign's normalization (X-Mme-Client-Info, lowercase "me")
        if k.lower() == "x-mme-client-info":
            k = "X-Mme-Client-Info"
        headers[k] = v

    # normalize client time to UTC "....Z" like plumesign's provider emits
    ct = headers.get("X-Apple-I-Client-Time", "")
    try:
        dt = _dt.datetime.fromisoformat(ct.replace("Z", "+00:00"))
        headers["X-Apple-I-Client-Time"] = (
            dt.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        )
    except Exception:
        pass
    return headers


def main() -> int:
    env = load_env()
    email = env["APPLE_ID"]
    password = env["APPLE_APP_PASSWORD"]
    email_l = email.lower()

    import urllib3

    # gsa.apple.com's chain ends in Apple Root CA (self-signed), which the
    # Linux CA bundle lacks — use system bundle + Apple root (same as plumesign).
    ca = REPO / "build" / "ca-bundle.pem"
    if not ca.exists():
        print(f"missing {ca}; run: cat /etc/ssl/certs/ca-certificates.crt build/apple-root.pem > build/ca-bundle.pem")
        return 1
    http = urllib3.PoolManager(ca_certs=str(ca))
    headers = anisette_headers()
    cpd = dict(headers)
    cpd.update(
        {
            "bootstrap": "true",
            "icscrec": "true",
            "loc": "en_GB",
            "pbe": "false",
            "prkgen": "true",
            "svct": "iCloud",
        }
    )

    req_headers = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "*/*",
        "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
        # plumesign lowercases the value via get_header()
        "X-Mme-Client-Info": headers["X-Mme-Client-Info"].lower(),
    }

    a = secrets.token_bytes(32)
    A = pow(G, int.from_bytes(a, "big"), N)
    A_b = _trim(A)

    init = {
        "Header": {"Version": "1.0.1"},
        "Request": {
            "A2k": A_b,
            "cpd": cpd,
            "o": "init",
            "ps": ["s2k", "s2k_fo"],
            "u": email_l,
        },
    }
    r = http.request(
        "POST", GSA, body=plistlib.dumps(init, fmt=plistlib.FMT_XML), headers=req_headers
    )
    print(f"[init] HTTP {r.status}")
    res = plistlib.loads(r.data)
    print(f"[init] keys: {sorted(res.keys())}")
    st = res.get("Status")
    ec = res.get("ec", (st or {}).get("ec") if isinstance(st, dict) else None)
    if ec not in (None, 0):
        em = res.get("em", (st or {}).get("em") if isinstance(st, dict) else None)
        print(f"[init] ERROR ec={ec} em={em!r}")
        return 1

    s = res["s"]
    B_b = res["B"]
    iters = res["i"]
    c = res["c"]
    B = int.from_bytes(B_b, "big")
    print(f"[init] salt={len(s)}B B={len(B_b)}B iters={iters} c={c[:8]}...")

    # s2k password derivation: PBKDF2(SHA256(password), salt, iters)
    hashed_pw = hashlib.sha256(password.encode()).digest()
    pw_buf = hashlib.pbkdf2_hmac("sha256", hashed_pw, s, iters, 32)

    # SRP-6a, Apple variant (username_in_x = false)
    identity_hash = hashlib.sha256(b":" + pw_buf).digest()
    x = int.from_bytes(hashlib.sha256(s + identity_hash).digest(), "big")
    u = int.from_bytes(hashlib.sha256(_pad(A_b) + _pad(B_b)).digest(), "big")
    k = int.from_bytes(
        hashlib.sha256(N.to_bytes(NLEN, "big") + _pad(G.to_bytes(1, "big"))).digest(),
        "big",
    )
    S = pow((B - k * pow(G, x, N)) % N, int.from_bytes(a, "big") + u * x, N)
    S_b = _trim(S)
    K = hashlib.sha256(S_b).digest()

    hN = hashlib.sha256(N.to_bytes(NLEN, "big")).digest()
    hg = hashlib.sha256(_pad(G.to_bytes(1, "big"))).digest()
    n_xor_g = bytes(p ^ q for p, q in zip(hN, hg))
    M1 = hashlib.sha256(
        n_xor_g + hashlib.sha256(email_l.encode()).digest() + s + A_b + B_b + K
    ).digest()

    comp = {
        "Header": {"Version": "1.0.1"},
        "Request": {
            "M1": M1,
            "cpd": cpd,
            "c": c,
            "o": "complete",
            "u": email_l,
        },
    }
    r2 = http.request(
        "POST",
        GSA,
        body=plistlib.dumps(comp, fmt=plistlib.FMT_XML),
        headers={**req_headers, "Connection": "close"},
    )
    print(f"[complete] HTTP {r2.status}")
    res2 = plistlib.loads(r2.data)
    print(f"[complete] keys: {sorted(res2.keys())}")
    st2 = res2.get("Status")
    ec2 = res2.get("ec", (st2 or {}).get("ec") if isinstance(st2, dict) else None)
    if ec2 not in (None, 0):
        em2 = res2.get("em", (st2 or {}).get("em") if isinstance(st2, dict) else None)
        print(f"[complete] ERROR ec={ec2} em={em2!r}")
        print("RESULT: Apple rejected the SRP proof (wrong password / wrong account).")
        return 1

    M2 = res2["M2"]
    M2_check = hashlib.sha256(A_b + M1 + K).digest()
    print(f"[complete] M2 server-proof valid: {M2 == M2_check}")

    # decrypt spd (AES-256-CBC, key/iv = HMAC-SHA256(premaster, label))
    key = _hmac.new(S_b, b"extra data key:", hashlib.sha256).digest()
    iv = _hmac.new(S_b, b"extra data iv:", hashlib.sha256).digest()[:16]
    from Crypto.Cipher import AES  # type: ignore
    from Crypto.Util.Padding import unpad  # type: ignore

    spd = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(res2["spd"]), 16)
    spd_plist = plistlib.loads(spd)
    dsid = spd_plist.get("dsInfo", {}).get("dsid", "?")
    print(f"[complete] LOGIN OK — dsid={dsid}")
    print(f"[complete] spd keys: {sorted(spd_plist.keys())}")
    print("RESULT: SRP login SUCCEEDED with local anisette — password is valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
