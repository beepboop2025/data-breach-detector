#!/usr/bin/env python3
"""Stand-in for a retired hosted endpoint: says where the tool went, then gets out of the way.

The hosted remote was retired on 23 November 2026; the package is the product.
For a notice window this process takes the retired server's port, so existing
clients get a readable answer instead of a dead socket:

* MCP POSTs get HTTP 410 with a JSON-RPC error naming the replacement, echoing
  the request id when there is one, so a client shows the message.
* Everything else gets HTTP 410 with the same message as plain text.
* One optional proof file (RETIRED_PROOF_NAME + RETIRED_PROOF_BODY) lets a
  directory confirm that a delisting request comes from whoever runs this host.

Standard library only, no state, nothing logged beyond the HTTP status line.
"""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RETIRED_ON = "2026-11-23"
MESSAGE = (
    "The hosted data-breach-detector endpoint was retired on 23 November 2026. "
    "Run it locally instead, with the same tools: pip install data-breach-detector "
    "(MIT). Source: https://github.com/beepboop2025/data-breach-detector"
)
PROOF_NAME = os.environ.get("RETIRED_PROOF_NAME", "").strip("/")
PROOF_BODY = os.environ.get("RETIRED_PROOF_BODY", "")
MAX_BODY = 65536


class Notice(BaseHTTPRequestHandler):
    server_version = "retired-endpoint"
    sys_version = ""
    timeout = 10  # socket timeout: a slow sender cannot hold a thread open

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Retired-On", RETIRED_ON)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _text(self, status: int = 410) -> None:
        self._send(status, (MESSAGE + "\n").encode(), "text/plain; charset=utf-8")

    def do_POST(self) -> None:  # noqa: N802 (http.server naming)
        rid = None
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        # Read only a declared, bounded body. A negative length would make
        # read() consume the stream until the client closes it, and an
        # oversized one is answered without being read at all.
        if 0 < length <= MAX_BODY:
            try:
                payload = json.loads(self.rfile.read(length))
                candidate = payload.get("id") if isinstance(payload, dict) else None
                if isinstance(candidate, (str, int)) and not isinstance(candidate, bool):
                    rid = candidate
            except (ValueError, OSError):
                pass
        self.close_connection = True
        body = {"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": MESSAGE}}
        self._send(410, json.dumps(body).encode(), "application/json")

    def do_GET(self) -> None:  # noqa: N802
        if PROOF_NAME and PROOF_BODY and self.path.split("?", 1)[0] == f"/.well-known/{PROOF_NAME}":
            self._send(200, (PROOF_BODY + "\n").encode(), "text/plain; charset=utf-8")
            return
        self._text()

    do_HEAD = do_GET
    do_DELETE = _text
    do_PUT = _text
    do_PATCH = _text

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._text()

    def log_message(self, fmt: str, *args) -> None:
        # Status line only: no paths, no query strings, no client addresses.
        if args and isinstance(args[0], str) and args[0].count(" ") >= 2:
            print(f"{self.command} -> {args[1] if len(args) > 1 else ''}", flush=True)


def main() -> None:
    host = os.environ.get("RETIRED_HOST", "127.0.0.1")
    port = int(os.environ.get("RETIRED_PORT", "8790"))
    ThreadingHTTPServer((host, port), Notice).serve_forever()


if __name__ == "__main__":
    main()
