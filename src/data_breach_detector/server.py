"""data_breach_detector — a read-only breach-intelligence MCP server.

DEFENSIVE ONLY. Answers "has X been breached / what's the recent breach news /
how severe is this threat text" from PUBLIC threat-intelligence disclosure
feeds. It reports INTELLIGENCE — the existence, timing, scale, category and
exposed data-TYPES of a breach — and never the breach CONTENTS. A redaction
pass strips emails, hashes, IPs, crypto addresses and credential-shaped tokens
from everything returned.

Live public sources (no key, no marketplace, no Tor):
  - HaveIBeenPwned  https://haveibeenpwned.com/api/v3/breaches
      the public breach directory: domain, date, pwn count, and the CATEGORIES
      of data exposed (e.g. "Email addresses, Passwords") — never the values.
  - ransomwatch     joshhighet/ransomwatch (public ransomware leak-site tracker)

It exposes no arbitrary fetch/crawl/proxy, no .onion access, no transactions,
and never returns the raw text of a dump, paste or leak.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from datetime import datetime, timezone

import httpx
from mcp.server.fastmcp import FastMCP

from .classifier import classify_threat

# httpx logs full request URLs at INFO; when the HTTP transport is fronted by a
# token nothing sensitive is in these URLs, but keep logs quiet regardless.
for _n in ("httpx", "httpcore"):
    logging.getLogger(_n).setLevel(logging.WARNING)

mcp = FastMCP("data_breach_detector")

HIBP_BREACHES = "https://haveibeenpwned.com/api/v3/breaches"
RANSOMWATCH = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
_UA = "data-breach-detector/0.1 (+defensive threat-intel)"
_SEVERITY = ["low", "medium", "high", "critical"]

_REDACTIONS = [
    (re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "[email]"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[ip]"),
    (re.compile(r"\b[a-fA-F0-9]{32,64}\b"), "[hash]"),
    (re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"), "[btc]"),
    (re.compile(r"\b0x[a-fA-F0-9]{40}\b"), "[eth]"),
    (re.compile(r"\S+:\S{4,}"), "[credential]"),
    (re.compile(r"\b[A-Za-z0-9+/=_-]{24,}\b"), "[token]"),
]


def _redact(text: str, cap: int = 320) -> str:
    if not text:
        return ""
    out = text
    for pattern, repl in _REDACTIONS:
        out = pattern.sub(repl, out)
    out = re.sub(r"<[^>]+>", " ", out)
    out = re.sub(r"\s+", " ", out).strip()
    return out[:cap]


def _sev_rank(level: str) -> int:
    return _SEVERITY.index(level) if level in _SEVERITY else 0


_CACHE: dict = {"at": 0.0, "items": []}
_TTL_S = 900


async def _fetch_hibp(client: httpx.AsyncClient) -> list[dict]:
    r = await client.get(HIBP_BREACHES)
    r.raise_for_status()
    out = []
    for b in r.json():
        data_types = b.get("DataClasses", []) or []
        cls = classify_threat(f"{b.get('Title','')} {b.get('Description','')} {' '.join(data_types)}")
        base = cls["threat_level"]
        if any("password" in d.lower() or "credential" in d.lower() for d in data_types):
            base = "critical" if b.get("IsStealerLog") else "high"
        out.append({
            "id": f"hibp:{b.get('Name')}",
            "entity": b.get("Domain") or b.get("Name"),
            "title": _redact(b.get("Title") or b.get("Name"), 120),
            "summary": _redact(b.get("Description", "")),
            "source": "HaveIBeenPwned",
            "source_url": b.get("DisclosureUrl") or f"https://haveibeenpwned.com/PwnedWebsites#{b.get('Name')}",
            "disclosed_at": (b.get("BreachDate") or "") + ("T00:00:00+00:00" if b.get("BreachDate") else ""),
            "sort_date": b.get("AddedDate") or b.get("BreachDate", ""),
            "pwn_count": b.get("PwnCount", 0),
            "exposed_data_types": data_types,
            "categories": list(cls["categories"].keys()) or ["data_breach"],
            "threat_level": base,
            "verified": bool(b.get("IsVerified")),
            "stealer_log": bool(b.get("IsStealerLog")),
        })
    return out


async def _fetch_ransomwatch(client: httpx.AsyncClient) -> list[dict]:
    r = await client.get(RANSOMWATCH)
    r.raise_for_status()
    posts = r.json()
    posts.sort(key=lambda p: p.get("discovered", ""), reverse=True)
    out = []
    for p in posts[:120]:
        title, group = p.get("post_title", ""), p.get("group_name", "")
        cls = classify_threat(f"ransomware leak site {group} {title}")
        out.append({
            "id": f"ransomwatch:{group}:{title}"[:120],
            "entity": _redact(title, 120),
            "title": _redact(f"[{group}] {title}", 140),
            "summary": _redact(f"Named on the {group} ransomware leak site."),
            "source": "ransomwatch",
            "source_url": "https://github.com/joshhighet/ransomwatch",
            "disclosed_at": (p.get("discovered", "") or "").replace(" ", "T") + "+00:00" if p.get("discovered") else "",
            "sort_date": p.get("discovered", ""),
            "pwn_count": 0,
            "exposed_data_types": [],
            "categories": list(cls["categories"].keys()) or ["ransomware"],
            "threat_level": "high",
            "verified": True,
            "stealer_log": False,
            "actor": group,
        })
    return out


async def _feed() -> list[dict]:
    now = time.time()
    if _CACHE["items"] and now - _CACHE["at"] < _TTL_S:
        return _CACHE["items"]
    records: list[dict] = []
    async with httpx.AsyncClient(timeout=25, headers={"User-Agent": _UA},
                                 follow_redirects=True) as client:
        results = await asyncio.gather(_fetch_hibp(client), _fetch_ransomwatch(client),
                                       return_exceptions=True)
    for res in results:
        if isinstance(res, list):
            records.extend(res)
    records.sort(key=lambda r: r.get("sort_date", ""), reverse=True)
    _CACHE.update(at=now, items=records)
    return records


def _days_ago(iso: str | None) -> float:
    if not iso:
        return 1e9
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).total_seconds() / 86400
    except (ValueError, TypeError):
        return 1e9


@mcp.tool()
async def breach_news(since_days: int = 30, sector: str | None = None, limit: int = 25) -> dict:
    """Recent breach and ransomware DISCLOSURES from public threat-intel feeds
    (HaveIBeenPwned, ransomwatch). Metadata only — entity, date, scale, exposed
    data TYPES, threat level — never the leaked data. Optional sector/keyword
    filter (e.g. "bank", "health", "crypto")."""
    feed = await _feed()
    rows = [r for r in feed if _days_ago(r.get("sort_date")) <= since_days]
    if sector:
        s = sector.lower()
        rows = [r for r in rows if s in (
            r["title"] + " " + r["summary"] + " " + " ".join(r["categories"])
            + " " + " ".join(r["exposed_data_types"])).lower()]
    return {"count": len(rows), "since_days": since_days, "sector": sector,
            "disclosures": rows[:limit],
            "note": "Disclosure metadata only. No leaked records are served by this tool."}


@mcp.tool()
async def check_exposure(query: str, since_days: int = 100000) -> dict:
    """Does a domain, company or brand appear in public breach or ransomware
    DISCLOSURES? The HaveIBeenPwned model: yes/no plus metadata (when, scale,
    which data types were exposed, severity, source) — never the exposed
    records. Triage only; confirm through authorized channels."""
    q = query.strip().lower()
    if not q:
        return {"error": "query is required (a domain, company or brand)"}
    feed = await _feed()
    hits = [r for r in feed if _days_ago(r.get("sort_date")) <= since_days and q in (
        r["entity"] + " " + r["title"] + " " + r["summary"]).lower()]
    worst = max((h["threat_level"] for h in hits), key=_sev_rank, default="none")
    return {
        "query": query, "exposed": bool(hits), "mentions": len(hits),
        "worst_threat_level": worst if hits else "none",
        "total_accounts_exposed": sum(h["pwn_count"] for h in hits),
        "exposed_data_types": sorted({t for h in hits for t in h["exposed_data_types"]}),
        "latest_disclosure": hits[0]["sort_date"] if hits else None,
        "matches": hits[:15],
        "note": ("Presence signal from public disclosure feeds: reports THAT an entity "
                 "appears in breach data, not the breached data. Confirm before acting."),
    }


@mcp.tool()
async def assess_threat(text: str) -> dict:
    """Triage a piece of security text (advisory, forum post, alert): classify
    threat level, categories and recommended action. Pure analysis of text you
    supply — collects nothing, reaches no network."""
    if not text or not text.strip():
        return {"error": "text is required"}
    r = classify_threat(text)
    return {"threat_level": r["threat_level"], "categories": list(r["categories"].keys()),
            "financial_targets": r["financial_targets"], "confidence": r["confidence"],
            "recommended_action": r["recommended_action"]}


@mcp.tool()
async def feed_sources() -> dict:
    """List the public feeds this detector aggregates and how fresh the cache is."""
    feed = await _feed()
    by_source: dict[str, int] = {}
    for r in feed:
        by_source[r["source"]] = by_source.get(r["source"], 0) + 1
    return {
        "sources": ["HaveIBeenPwned — breach directory (domain, count, exposed data types)",
                    "ransomwatch — ransomware leak-site tracker (named victims)"],
        "cached_disclosures": len(feed), "by_source": by_source,
        "cache_age_seconds": int(time.time() - _CACHE["at"]) if _CACHE["at"] else None,
        "scope": ("Public disclosure feeds only. No .onion access, no arbitrary "
                  "fetch/crawl, no credential or PII output."),
    }
