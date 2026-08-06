<!-- mcp-name: io.github.beepboop2025/data-breach-detector -->

# data-breach-detector

A **read-only breach-intelligence MCP server**. It answers *"has this
organization ever been breached, what's the recent breach news, what does two
decades of breach history look like, how severe is this threat text"* from
public disclosure feeds — and reports **intelligence, not contents**: the
existence, timing, scale, category and exposed data-*types* of a breach, never
the leaked records themselves.

Built for defensive investigation and automated security workflows.

## Design choices

The server differs from several common breach-data products:

- **Consumer checkers** (HaveIBeenPwned's site) answer one question — "is my
  email in a breach" — one account at a time, one source at a time.
- **Leak-data brokers** (DeHashed, IntelX, LeakCheck and similar services) sell
  access to leaked records. Passing those records into a downstream workflow
  creates an additional disclosure risk.
- **Enterprise intelligence platforms** (SpyCloud, Recorded Future, Flashpoint)
  combine multiple sources through commercial products and APIs.

This server takes a fourth position:

1. **Four primary sources, one queryable surface.** The verified breach
   directory (HIBP), a *live* ransomware leak-site tracker (RansomLook), a
   ~16k-victim leak-site archive back to 2020 (ransomwatch), and SEC 8-K
   Item 1.05 filings — companies' own legally mandated "material cybersecurity
   incident" disclosures. The sources are queried through one index.
2. **History is first-class.** `breach_history`, `breach_timeline` and
   `breach_stats` treat 2007→today as the product, not a cache: every breach
   of 2013, an organization's full incident chronology, repeat-victim
   flagging, per-year and per-actor aggregates.
3. **The ethical boundary is in the code, not the terms of service.** No
   fetch/crawl/proxy primitives, no `.onion` access, and every feed-authored
   string is sanitized *where the record is built*, before any field is
   assembled from it: emails, hashes, IPs, crypto addresses and
   credential-shaped tokens are redacted, and the invisible channels used to
   hide instructions from a human reader (Unicode Tags, zero-widths, bidi
   overrides, variation selectors, terminal control codes) are stripped. That
   matters because leak-site titles are written by ransomware crews and may be
   read by a language model: the same field is both intelligence and an injection surface.
   Redacting only the two fields a human looks at is not enough, because ids,
   actor names and statistic bucket keys are built from the same strings.
4. **Source health is explicit.** `feed_sources` reports each feed's newest
   item, a staleness flag and the last fetch error — a dead upstream is a
   served fact, not a silent hole. (The ransomwatch project itself froze in
   June 2025; this server says so instead of pretending.)
5. **MCP transport.** Install with `pip`; run over stdio or streamable HTTP.

## What it does not do

- No arbitrary URL fetch, no crawl, no proxy — no general scraping primitives.
- No `.onion` marketplace access, no transactions.
- Never returns the raw text of a dump, paste or leak. Feed-authored strings are
  redacted and stripped of hidden-instruction characters at the point each
  record is constructed, so ids, actor names, entity names, dates, source URLs
  and aggregation keys are built from sanitized values rather than raw ones.

## Sources (public, no key)

- **HaveIBeenPwned** `/api/v3/breaches` — the verified breach directory back
  to 2007: domain, breach date, pwn count, exposed data *categories*.
- **RansomLook** (`ransomlook.io`) — live ransomware leak-site tracker.
- **ransomwatch** (`joshhighet/ransomwatch`) — frozen archive of ~16k
  leak-site posts, Jan 2020 → Jun 2025, retained as history.
- **SEC EDGAR** — 8-K filings carrying Item 1.05 *Material Cybersecurity
  Incidents* (mandatory first-party disclosure since Dec 2023).

## Tools

| tool | what it returns |
|------|-----------------|
| `breach_news(since_days, sector, source, limit, offset)` | recent disclosures — entity, date, scale, exposed data types, severity |
| `check_exposure(query, since_days, limit, offset)` | does a domain/company appear anywhere in breach data — yes/no + metadata |
| `breach_history(query, year_from, year_to, sector, data_type, min_accounts, order, limit, offset)` | search the full archive back to 2007 |
| `breach_timeline(entity, limit, offset)` | one organization's incident-by-incident chronology + repeat-victim assessment |
| `breach_stats(group_by, sector, limit)` | aggregates per year / source / data type / threat level / ransomware actor |
| `assess_threat(text)` | classify a piece of security text — level, categories, action (no network) |
| `feed_sources()` | feeds, per-source freshness, staleness flags, last fetch errors |

Every list tool reports `count`, `limit`, `offset` and `returned`, and
`breach_stats` reports `buckets_total`, so a truncated answer is visible as
truncated and the tail is reachable by paging rather than lost.

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

Hosted remote: `https://breach.seiche.info/mcp`

## License

MIT. The breach data belongs to its sources (HaveIBeenPwned, RansomLook,
ransomwatch, SEC EDGAR); this tool only aggregates their public disclosure
metadata, with attribution.
