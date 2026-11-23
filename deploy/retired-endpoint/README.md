# Retired hosted endpoint

The hosted remote was retired on 23 November 2026 with v0.4.0. The package is
the product: `pip install data-breach-detector`, then run it over stdio or
self-host it with `data-breach-detector --http`.

For a 30-day notice window, `notice.py` takes the retired server's loopback
port, so existing clients get a readable HTTP 410 naming the replacement
instead of a dead socket. MCP POSTs get a JSON-RPC error that echoes the
request id; everything else gets the same message as plain text.

## Install on the host (root)

```sh
install -D -m 0644 notice.py /opt/breach-mcp/retired/notice.py
mkdir -p /etc/systemd/system/breach-mcp.service.d
cat > /etc/systemd/system/breach-mcp.service.d/zz-retired.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/python3 -I /opt/breach-mcp/retired/notice.py
# Optional, for a directory delisting check:
# Environment=RETIRED_PROOF_NAME=<file name> RETIRED_PROOF_BODY=<text>
EOF
systemctl daemon-reload && systemctl restart breach-mcp.service
```

Check: a POST to the public hostname returns 410 with the JSON-RPC message.

Rollback: remove `zz-retired.conf`, `systemctl daemon-reload`, restart the
service. The previous server stays installed in its virtualenv until the
window closes.

## Registry

Version 0.4.0 lists no remote, but the MCP registry keeps every version, and
0.1.0 to 0.3.2 still list the retired endpoint. Mark them deprecated so a
directory that reads every version sees the retirement:

```sh
gh workflow run registry-status.yml -f status=deprecated \
  -f versions="0.1.0 0.2.0 0.2.2 0.3.0 0.3.1 0.3.2" \
  -f message="The hosted endpoint was retired on 23 November 2026. Version 0.4.0 runs locally: pip install data-breach-detector."
```

`-f status=active` with no message undoes it.

## Close the window (on or after 23 December 2026)

1. Delete the hostname's DNS record.
2. `systemctl disable --now breach-mcp.service` and remove `/opt/breach-mcp`.
3. Remove the hostname's block from the reverse-proxy configuration.
4. Optionally hide the old versions from default registry listings: the
   registry command above with `-f status=deleted`.
