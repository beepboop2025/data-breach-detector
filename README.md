<!-- mcp-name: io.github.beepboop2025/data-breach-detector -->

# data-breach-detector

A **read-only breach-intelligence MCP server**. It answers *"has this domain
been breached, what's the recent breach news, how severe is this threat text"*
from public threat-intelligence disclosure feeds — and reports **intelligence,
not contents**: the existence, timing, scale, category and exposed data-*types*
of a breach, never the leaked records themselves.

Built for defenders. Comparable in spirit to HaveIBeenPwned's own directory.

## What it does not do

- No arbitrary URL fetch, no crawl, no proxy — no general scraping primitives.
- No `.onion` marketplace access, no transactions.
- Never returns the raw text of a dump, paste or leak. A redaction layer strips
  emails, hashes, IPs, crypto addresses and credential-shaped tokens from every
  string returned.

## Sources (public, no key)

- **HaveIBeenPwned** `/api/v3/breaches` — the public breach directory: domain,
  breach date, pwn count, and the *categories* of data exposed.
- **ransomwatch** (`joshhighet/ransomwatch`) — public ransomware leak-site tracker.

## Tools

| tool | what it returns |
|------|-----------------|
| `breach_news(since_days, sector, limit)` | recent disclosures — entity, date, scale, exposed data types, severity |
| `check_exposure(query)` | does a domain/company appear in breach data — yes/no + metadata |
| `assess_threat(text)` | classify a piece of security text — level, categories, action (no network) |
| `feed_sources()` | which feeds are aggregated + cache freshness |

## Run

```bash
pip install data-breach-detector

data-breach-detector           # stdio (for MCP clients)
data-breach-detector --http    # streamable-HTTP on 127.0.0.1:8790/mcp
```

Or point an MCP client at the config:

```json
{ "mcpServers": { "data_breach_detector": {
  "command": "data-breach-detector"
} } }
```

## License

MIT. The breach data belongs to its sources (HaveIBeenPwned, ransomwatch);
this tool only aggregates their public disclosure metadata, with attribution.
