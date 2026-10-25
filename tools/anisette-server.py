#!/usr/bin/env python3
"""Local anisette v3 server for sideloading (AltServer / plumesign compatible).

Wraps Anisette.py (installed in build/venv) and serves anisette headers on
127.0.0.1:6969. Two fixes over the stock `anisette serve` CLI:

  * X-Apple-I-Client-Time is emitted in the strict UTC form
    "YYYY-MM-DDTHH:MM:SSZ" that AltServer/plumesign require (the stock CLI
    appends the local UTC offset, which AltServer rejects).
  * X-Apple-I-TimeZone is pinned to "UTC".

The provisioning session (OTP counter) is saved after every request, same as
the stock CLI.

Usage:  build/venv/bin/python tools/anisette-server.py [--port 6969]
Point tools at it with:  ALTSERVER_ANISETTE_SERVER=http://127.0.0.1:6969
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ANI_DIR = REPO / "build" / "anisette-config" / "anisette-py"
LIBS = ANI_DIR / "libs.bin"
PROV = ANI_DIR / "default.prov"

os.environ.setdefault("XDG_CONFIG_HOME", str(REPO / "build" / "anisette-config"))


def get_data() -> dict:
    from anisette import Anisette  # type: ignore

    ani = Anisette.load(str(LIBS), str(PROV))
    data = dict(ani.get_data())
    ani.save_provisioning(str(PROV))

    now = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    data["X-Apple-I-Client-Time"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    data["X-Apple-I-TimeZone"] = "UTC"
    return data


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        try:
            body = json.dumps(get_data()).encode()
        except Exception as e:  # noqa: BLE001
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"anisette error: {e}".encode())
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:  # silence per-request logging
        pass


def main() -> int:
    port = 6969
    if "--port" in sys.argv:
        port = int(sys.argv[sys.argv.index("--port") + 1])
    if not LIBS.exists() or not PROV.exists():
        print(f"[FAIL] missing {LIBS} or {PROV} — create the session first:", file=sys.stderr)
        print("       build/venv/bin/anisette new default", file=sys.stderr)
        return 1
    print(f"[ok] serving local anisette on http://127.0.0.1:{port} (Ctrl-C to stop)")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
