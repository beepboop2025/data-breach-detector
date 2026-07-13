"""CLI entry point: stdio by default, streamable-HTTP with --http.

  data-breach-detector                 # stdio (for local / MCP clients)
  data-breach-detector --http          # HTTP MCP on 127.0.0.1:8790/mcp
  data-breach-detector --http --host 0.0.0.0 --port 8790
"""

from __future__ import annotations

import argparse

from .server import mcp


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="data-breach-detector",
                                 description="Read-only breach-intelligence MCP server")
    ap.add_argument("--http", action="store_true",
                    help="serve over streamable-HTTP instead of stdio")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8790)
    args = ap.parse_args(argv)

    if args.http:
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        mcp.run(transport="streamable-http")
    else:
        mcp.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
