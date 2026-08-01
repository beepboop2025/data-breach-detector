"""data_breach_detector — a read-only breach-intelligence MCP server.

DEFENSIVE ONLY. Answers "has X been breached / what's the recent breach news /
what does X's full breach history look like / how severe is this threat text"
from PUBLIC threat-intelligence disclosure feeds. It reports INTELLIGENCE —
the existence, timing, scale, category and exposed data-TYPES of a breach —
and never the breach CONTENTS. A redaction pass strips emails, hashes, IPs,
crypto addresses and credential-shaped tokens from everything returned.

Live public sources (no key, no marketplace, no Tor):
  - HaveIBeenPwned   https://haveibeenpwned.com/api/v3/breaches
      the verified breach directory back to 2007: domain, date, pwn count and
      the CATEGORIES of data exposed — never the values.
  - RansomLook       https://www.ransomlook.io (live ransomware leak-site tracker)
  - ransomwatch      joshhighet/ransomwatch — frozen archive of ~16k leak-site
      posts, Jan 2020 → Jun 2025 (upstream stopped updating; kept as history).
  - SEC EDGAR        8-K filings with Item 1.05 "Material Cybersecurity
      Incidents" — first-party breach disclosures mandated since Dec 2023.

It exposes no arbitrary fetch/crawl/proxy, no .onion access, no transactions,
and never returns the raw text of a dump, paste or leak.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from datetime import datetime, timezone

from typing import Annotated

import httpx
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .classifier import classify_threat

# httpx logs full request URLs at INFO; when the HTTP transport is fronted by a
# token nothing sensitive is in these URLs, but keep logs quiet regardless.
for _n in ("httpx", "httpcore"):
    logging.getLogger(_n).setLevel(logging.WARNING)

mcp = FastMCP("data_breach_detector")

HIBP_BREACHES = "https://haveibeenpwned.com/api/v3/breaches"
RANSOMLOOK_RECENT = "https://www.ransomlook.io/api/recent"
RANSOMWATCH_ARCHIVE = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
SEC_FTS = "https://efts.sec.gov/LATEST/search-index"
_UA = "data-breach-detector/0.2 (+defensive threat-intel; contact@seiche.info)"
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


_DOMAIN = re.compile(r"\b([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+)\b")
_DOMAIN_SKIP = {"zoominfo.com", "linkedin.com", "wikipedia.org", "www.com"}


def _entity_domain(text: str) -> str | None:
    """Best-effort victim domain from a leak-site post description."""
    for tok in (text or "").lower().split():
        if "@" in tok:
            continue
        m = _DOMAIN.search(tok)
        if m:
            dom = m.group(1).removeprefix("www.")
            root = ".".join(dom.split(".")[-2:])
            if root not in _DOMAIN_SKIP and dom not in _DOMAIN_SKIP:
                return dom
    return None


def _ransom_record(group: str, title: str, discovered: str, summary: str,
                   source: str, source_url: str, classify: bool) -> dict:
    entity = _entity_domain(summary) or _redact(title, 120)
    cats = ["ransomware"]
    if classify:
        cls = classify_threat(f"ransomware leak site {group} {title} {summary[:200]}")
        cats = list(cls["categories"].keys()) or cats
    iso = discovered.replace(" ", "T")[:19] + "+00:00" if discovered else ""
    return {
        "id": f"{source}:{group}:{title}"[:120],
        "entity": entity,
        "title": _redact(f"[{group}] {title}", 140),
        "summary": _redact(summary or f"Named on the {group} ransomware leak site."),
        "source": source,
        "source_url": source_url,
        "disclosed_at": iso,
        "sort_date": discovered or "",
        "pwn_count": 0,
        "exposed_data_types": [],
        "categories": cats,
        "threat_level": "high",
        "verified": True,
        "stealer_log": False,
        "actor": group,
    }


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


async def _fetch_ransomlook(client: httpx.AsyncClient) -> list[dict]:
    r = await client.get(RANSOMLOOK_RECENT)
    r.raise_for_status()
    out = []
    for p in r.json():
        out.append(_ransom_record(
            group=p.get("group_name", ""), title=p.get("post_title", ""),
            discovered=p.get("discovered", ""), summary=p.get("description") or "",
            source="RansomLook", source_url="https://www.ransomlook.io",
            classify=True))
    return out


async def _fetch_ransomwatch_archive(client: httpx.AsyncClient) -> list[dict]:
    r = await client.get(RANSOMWATCH_ARCHIVE)
    r.raise_for_status()
    posts = r.json()
    posts.sort(key=lambda p: p.get("discovered", ""), reverse=True)
    # Full history on purpose: this feed froze in Jun 2025 and is kept as the
    # 2020-2025 ransomware archive. Skip per-post classification at this scale.
    return [_ransom_record(
        group=p.get("group_name", ""), title=p.get("post_title", ""),
        discovered=p.get("discovered", ""), summary="",
        source="ransomwatch-archive",
        source_url="https://github.com/joshhighet/ransomwatch",
        classify=False) for p in posts]


async def _fetch_sec_incidents(client: httpx.AsyncClient) -> list[dict]:
    """8-K filings carrying Item 1.05 (Material Cybersecurity Incidents).

    EDGAR full-text search pages 10 hits at a time with no date sort, so page
    until every hit for the query is in hand (the population is small; a
    truncation note is surfaced by feed_sources if it ever outgrows the cap).
    """
    out, seen, total = [], set(), None
    for offset in range(0, 100, 10):
        r = await client.get(SEC_FTS, params={
            "q": '"Item 1.05"', "forms": "8-K", "from": offset})
        r.raise_for_status()
        payload = r.json()
        hits = payload.get("hits", {})
        total = hits.get("total", {}).get("value", 0)
        batch = hits.get("hits", [])
        if not batch:
            break
        for h in batch:
            src = h.get("_source", {})
            if "1.05" not in (src.get("items") or []):
                continue
            adsh = src.get("adsh", "")
            if not adsh or adsh in seen:
                continue
            seen.add(adsh)
            name = (src.get("display_names") or ["?"])[0]
            name = re.sub(r"\s*\(CIK \d+\)\s*$", "", name).strip()
            cik = (src.get("ciks") or ["0"])[0].lstrip("0") or "0"
            doc = h.get("_id", "").split(":", 1)[-1]
            fdate = src.get("file_date", "")
            out.append({
                "id": f"sec:{adsh}",
                "entity": name,
                "title": _redact(f"{name} — 8-K Item 1.05 material cybersecurity incident", 140),
                "summary": _redact(
                    f"{name} filed a Form {src.get('form','8-K')} disclosing a material "
                    f"cybersecurity incident under Item 1.05 on {fdate}."),
                "source": "SEC EDGAR 8-K 1.05",
                "source_url": f"https://www.sec.gov/Archives/edgar/data/{cik}/"
                              f"{adsh.replace('-', '')}/{doc}",
                "disclosed_at": fdate + ("T00:00:00+00:00" if fdate else ""),
                "sort_date": fdate,
                "pwn_count": 0,
                "exposed_data_types": [],
                "categories": ["cyber_incident", "regulatory_disclosure"],
                "threat_level": "high",
                "verified": True,
                "stealer_log": False,
            })
        if offset + 10 >= min(total or 0, 100):
            break
        await asyncio.sleep(0.15)
    _SEC_STATE["total"], _SEC_STATE["fetched"] = total or 0, len(out)
    return out


_SEC_STATE: dict = {"total": 0, "fetched": 0}
# Per-feed cache: fetcher __name__ -> {"at": last good fetch, "items": [...]}.
# Feeds refresh independently so one failing source can never drop another's
# rows; a failed feed keeps its last good items and retries after _RETRY_S.
_FEEDS: dict[str, dict] = {}
_LIVE_TTL_S = 900
_ARCHIVE_TTL_S = 21600
_RETRY_S = 300
_LAST_ERRORS: dict[str, str] = {}
_log = logging.getLogger("data_breach_detector")


def _dedup(records: list[dict]) -> list[dict]:
    """Drop later duplicates of the same ransomware victim post.

    Live and archive trackers watch the same leak sites; key on
    (actor, normalized title) so a victim counts once. Non-ransomware rows
    always pass (their ids are already unique per source).
    """
    seen, out = set(), []
    for r in records:
        actor = r.get("actor")
        if actor:
            key = (actor.strip().lower(), r.get("title", "").strip().lower()[:100])
            if key in seen:
                continue
            seen.add(key)
        out.append(r)
    return out


async def _refresh(fetchers, ttl: float) -> list[dict]:
    now = time.time()
    due = []
    for f in fetchers:
        slot = _FEEDS.setdefault(f.__name__, {"at": 0.0, "items": []})
        if not slot["items"] or now - slot["at"] >= ttl:
            due.append(f)
    if due:
        async with httpx.AsyncClient(timeout=40, headers={"User-Agent": _UA},
                                     follow_redirects=True) as client:
            results = await asyncio.gather(*(f(client) for f in due),
                                           return_exceptions=True)
        for f, res in zip(due, results):
            name = f.__name__.removeprefix("_fetch_")
            slot = _FEEDS[f.__name__]
            if isinstance(res, list) and res:
                slot.update(at=now, items=res)
                _LAST_ERRORS.pop(name, None)
            else:
                # A down feed must be a served fact, never a silent hole:
                # keep the last good items, record the error, retry soon.
                _LAST_ERRORS[name] = ("empty result" if isinstance(res, list)
                                      else f"{type(res).__name__}: {res}")
                _log.warning("feed %s failed: %s", name, _LAST_ERRORS[name])
                slot["at"] = now - ttl + _RETRY_S
    return [r for f in fetchers for r in _FEEDS[f.__name__]["items"]]


_LIVE_FETCHERS = [_fetch_hibp, _fetch_ransomlook]
_ARCHIVE_FETCHERS = [_fetch_ransomwatch_archive, _fetch_sec_incidents]


async def _feed() -> list[dict]:
    live, archive = await asyncio.gather(
        _refresh(_LIVE_FETCHERS, _LIVE_TTL_S),
        _refresh(_ARCHIVE_FETCHERS, _ARCHIVE_TTL_S),
    )
    merged = _dedup(list(live) + list(archive))
    merged.sort(key=lambda r: r.get("sort_date", ""), reverse=True)
    return merged


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


def _year_of(r: dict) -> int | None:
    for field in ("disclosed_at", "sort_date"):
        v = r.get(field) or ""
        if len(v) >= 4 and v[:4].isdigit():
            return int(v[:4])
    return None


def _slim(r: dict, summary_cap: int = 140) -> dict:
    """Compact projection for list payloads.

    Full records carry prose summaries that add up fast: a 30-row timeline ran
    to ~13k tokens, which is enough to stall an agent's tool loop. Every field
    an analyst acts on is kept; only the narrative is trimmed.
    """
    out = dict(r)
    summary = r.get("summary") or ""
    out["summary"] = (summary[:summary_cap].rstrip() + "…"
                      if len(summary) > summary_cap else summary)
    return out


def _haystack(r: dict) -> str:
    return (r.get("entity", "") + " " + r.get("title", "") + " "
            + r.get("summary", "") + " " + " ".join(r.get("categories", []))
            + " " + " ".join(r.get("exposed_data_types", []))
            + " " + (r.get("actor") or "")).lower()


@mcp.tool(annotations=ToolAnnotations(
    title="Recent breach disclosures",
    readOnlyHint=True, idempotentHint=True, openWorldHint=True))
async def breach_news(
    since_days: Annotated[int, Field(
        description="look-back window in days over disclosure dates (default 30)",
        ge=1)] = 30,
    sector: Annotated[str | None, Field(
        description="optional keyword filter over entity, title, summary, categories "
                    "and exposed data types, e.g. 'bank', 'health', 'crypto'")] = None,
    source: Annotated[str | None, Field(
        description="optional source filter: 'HaveIBeenPwned', 'RansomLook', "
                    "'ransomwatch-archive' or 'SEC EDGAR 8-K 1.05'")] = None,
    limit: Annotated[int, Field(
        description="maximum disclosures to return (default 10; raise it "
                    "deliberately, large pages are heavy for an agent loop)",
        ge=1, le=100)] = 10,
) -> dict:
    """Read recent breach and ransomware DISCLOSURES from public threat-intel
    feeds (HaveIBeenPwned, the RansomLook live leak-site tracker and SEC 8-K
    Item 1.05 filings), newest first. Every row is metadata only — entity,
    date, scale, exposed data TYPES, threat level and source — never the
    leaked data, and a redaction pass strips anything credential-shaped before
    it is returned. Use sector to narrow to an industry keyword; for one
    specific organization use check_exposure; for all-time history use
    breach_history."""
    feed = await _feed()
    rows = [r for r in feed if _days_ago(r.get("sort_date")) <= since_days]
    if sector:
        s = sector.lower()
        rows = [r for r in rows if s in _haystack(r)]
    if source:
        s = source.lower()
        rows = [r for r in rows if s in r["source"].lower()]
    return {"count": len(rows), "since_days": since_days, "sector": sector,
            "returned": min(len(rows), limit),
            "disclosures": [_slim(r) for r in rows[:limit]],
            "note": "Disclosure metadata only. No leaked records are served by this tool."}


@mcp.tool(annotations=ToolAnnotations(
    title="Entity exposure check",
    readOnlyHint=True, idempotentHint=True, openWorldHint=True))
async def check_exposure(
    query: Annotated[str, Field(
        description="domain, company or brand to look up, e.g. 'example.com' or 'Acme'")],
    since_days: Annotated[int, Field(
        description="optional look-back window in days; the default covers all history",
        ge=1)] = 100000,
) -> dict:
    """Answer whether a domain, company or brand appears in public breach or
    ransomware DISCLOSURES across ALL history (2007 → today): yes/no with
    mention count, worst threat level, total accounts exposed across matches,
    the exposed data TYPES, and the matching disclosure metadata — never the
    exposed records themselves. This is a triage signal built from disclosure
    feeds, not proof of compromise; confirm through authorized channels before
    acting. For the incident-by-incident chronology of one entity, use
    breach_timeline; for a recent-news sweep, use breach_news."""
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
        "matches": [_slim(h) for h in hits[:8]],
        "note": ("Presence signal from public disclosure feeds: reports THAT an entity "
                 "appears in breach data, not the breached data. Confirm before acting."),
    }


@mcp.tool(annotations=ToolAnnotations(
    title="Historical breach search",
    readOnlyHint=True, idempotentHint=True, openWorldHint=True))
async def breach_history(
    query: Annotated[str | None, Field(
        description="optional keyword over entity, title, summary, actor and "
                    "data types; omit to browse the whole archive")] = None,
    year_from: Annotated[int | None, Field(
        description="earliest incident year to include, e.g. 2013", ge=2000)] = None,
    year_to: Annotated[int | None, Field(
        description="latest incident year to include, e.g. 2020", ge=2000)] = None,
    sector: Annotated[str | None, Field(
        description="industry keyword filter, e.g. 'bank', 'health', 'gaming'")] = None,
    data_type: Annotated[str | None, Field(
        description="require an exposed data type, e.g. 'passwords', "
                    "'credit card', 'health'")] = None,
    min_accounts: Annotated[int, Field(
        description="only incidents exposing at least this many accounts", ge=0)] = 0,
    order: Annotated[str, Field(
        description="'newest' (default), 'oldest' or 'largest' (by accounts exposed)")] = "newest",
    limit: Annotated[int, Field(
        description="maximum incidents to return (default 10; raise it "
                    "deliberately, large pages are heavy for an agent loop)",
        ge=1, le=100)] = 10,
) -> dict:
    """Search the FULL historical breach archive — every incident this server
    knows about, back to 2007: HaveIBeenPwned's verified breach directory, the
    2020-2025 ransomwatch leak-site archive (~16k victims), the RansomLook
    live tracker and SEC 8-K Item 1.05 filings. Filter by keyword, year range,
    sector, exposed data type or minimum scale; order by date or size. Returns
    disclosure metadata only, never breach contents. Use this for questions
    like 'what were the biggest breaches of 2013' or 'which airlines have ever
    been hit by ransomware'."""
    feed = await _feed()
    rows = feed
    if query:
        s = query.lower()
        rows = [r for r in rows if s in _haystack(r)]
    if sector:
        s = sector.lower()
        rows = [r for r in rows if s in _haystack(r)]
    if data_type:
        s = data_type.lower()
        rows = [r for r in rows
                if any(s in t.lower() for t in r["exposed_data_types"])]
    if min_accounts:
        rows = [r for r in rows if r["pwn_count"] >= min_accounts]
    if year_from or year_to:
        lo, hi = year_from or 0, year_to or 9999
        rows = [r for r in rows
                if (y := _year_of(r)) is not None and lo <= y <= hi]
    if order == "largest":
        rows = sorted(rows, key=lambda r: r["pwn_count"], reverse=True)
    elif order == "oldest":
        rows = sorted(rows, key=lambda r: r.get("disclosed_at") or r.get("sort_date", ""))
    years = [y for r in rows if (y := _year_of(r)) is not None]
    return {
        "count": len(rows),
        "total_accounts_exposed": sum(r["pwn_count"] for r in rows),
        "span": {"earliest": min(years), "latest": max(years)} if years else None,
        "order": order,
        "returned": min(len(rows), limit),
        "incidents": [_slim(r) for r in rows[:limit]],
        "note": "Full-archive disclosure metadata only. No leaked records are served.",
    }


@mcp.tool(annotations=ToolAnnotations(
    title="Entity breach timeline",
    readOnlyHint=True, idempotentHint=True, openWorldHint=True))
async def breach_timeline(
    entity: Annotated[str, Field(
        description="domain, company or brand to build the chronology for, "
                    "e.g. 'yahoo.com' or 'Adobe'")],
) -> dict:
    """Build the complete incident-by-incident CHRONOLOGY of one organization
    across every source and all history, oldest first, with judgment on top:
    first and latest incident, incidents per year, whether the organization is
    a repeat victim, worst threat level and total accounts ever exposed.
    Repeat victimhood is a forward-looking risk signal — organizations named
    more than once have demonstrably not closed the gap. Metadata only; never
    the leaked data. For a yes/no presence check use check_exposure."""
    q = entity.strip().lower()
    if not q:
        return {"error": "entity is required (a domain, company or brand)"}
    feed = await _feed()
    hits = [r for r in feed if q in (
        r["entity"] + " " + r["title"] + " " + r["summary"]).lower()]
    hits.sort(key=lambda r: r.get("disclosed_at") or r.get("sort_date", ""))
    by_year: dict[str, int] = {}
    for r in hits:
        y = _year_of(r)
        if y is not None:
            by_year[str(y)] = by_year.get(str(y), 0) + 1
    worst = max((h["threat_level"] for h in hits), key=_sev_rank, default="none")
    repeat = len(hits) >= 2
    if not hits:
        stance = "No public disclosure on record for this entity. Absence of evidence only."
    elif repeat:
        stance = ("Repeat victim: named in multiple public disclosures. Treat "
                  "credentials and data shared with this organization as exposed; "
                  "expect above-baseline recurrence risk.")
    else:
        stance = ("Single known disclosure. Review what data types were exposed "
                  "and whether they are still in circulation.")
    return {
        "entity": entity,
        "incidents": len(hits),
        "repeat_victim": repeat,
        "first_incident": (hits[0].get("disclosed_at") or hits[0].get("sort_date")) if hits else None,
        "latest_incident": (hits[-1].get("disclosed_at") or hits[-1].get("sort_date")) if hits else None,
        "incidents_by_year": by_year,
        "worst_threat_level": worst if hits else "none",
        "total_accounts_exposed": sum(h["pwn_count"] for h in hits),
        "sources": sorted({h["source"] for h in hits}),
        "timeline": [_slim(h) for h in hits[:12]],
        "assessment": stance,
        "note": "Chronology of public disclosures only. No leaked records are served.",
    }


@mcp.tool(annotations=ToolAnnotations(
    title="Breach archive statistics",
    readOnlyHint=True, idempotentHint=True, openWorldHint=True))
async def breach_stats(
    group_by: Annotated[str, Field(
        description="aggregation axis: 'year' (default), 'source', 'data_type', "
                    "'threat_level' or 'actor' (ransomware group)")] = "year",
    sector: Annotated[str | None, Field(
        description="optional industry keyword filter applied before aggregating")] = None,
) -> dict:
    """Aggregate the full breach archive into analyst-grade statistics:
    incidents and accounts exposed per year, per source, per exposed data
    type, per threat level, or per ransomware actor — plus the five largest
    incidents ever recorded. Use it to answer 'how has breach volume trended
    since 2015', 'which ransomware groups have the most victims' or 'how often
    are passwords part of a breach'. Aggregate counts only; no leaked records."""
    feed = await _feed()
    if sector:
        s = sector.lower()
        feed = [r for r in feed if s in _haystack(r)]

    def keys_of(r: dict) -> list[str]:
        if group_by == "year":
            y = _year_of(r)
            return [str(y)] if y is not None else []
        if group_by == "source":
            return [r["source"]]
        if group_by == "data_type":
            return r["exposed_data_types"]
        if group_by == "threat_level":
            return [r["threat_level"]]
        if group_by == "actor":
            return [r["actor"]] if r.get("actor") else []
        return []

    if group_by not in ("year", "source", "data_type", "threat_level", "actor"):
        return {"error": "group_by must be one of: year, source, data_type, threat_level, actor"}
    buckets: dict[str, dict] = {}
    for r in feed:
        for k in keys_of(r):
            b = buckets.setdefault(k, {"incidents": 0, "accounts_exposed": 0})
            b["incidents"] += 1
            b["accounts_exposed"] += r["pwn_count"]
    ordered = sorted(buckets.items(),
                     key=lambda kv: (kv[1]["incidents"], kv[0]), reverse=True)
    if group_by == "year":
        ordered = sorted(buckets.items(), key=lambda kv: kv[0], reverse=True)
    largest = sorted(feed, key=lambda r: r["pwn_count"], reverse=True)[:5]
    return {
        "group_by": group_by, "sector": sector,
        "total_incidents": len(feed),
        "total_accounts_exposed": sum(r["pwn_count"] for r in feed),
        "buckets": {k: v for k, v in ordered[:40]},
        "largest_incidents": [
            {"entity": r["entity"], "title": r["title"], "pwn_count": r["pwn_count"],
             "disclosed_at": r["disclosed_at"], "source": r["source"]}
            for r in largest],
        "note": "Aggregates over public disclosure metadata only.",
    }


@mcp.tool(annotations=ToolAnnotations(
    title="Threat-text triage",
    readOnlyHint=True, idempotentHint=True, openWorldHint=False))
async def assess_threat(
    text: Annotated[str, Field(
        description="the security text to classify — an advisory, alert or forum post")],
) -> dict:
    """Classify a piece of security text you supply — an advisory, alert or
    forum post — into a threat level, matched categories, financial-target
    flags, a confidence score and a recommended action. Pure local analysis:
    it collects nothing, stores nothing and reaches no network; the text never
    leaves the server. Use it to triage findings surfaced by breach_news or
    from your own monitoring."""
    if not text or not text.strip():
        return {"error": "text is required"}
    r = classify_threat(text)
    return {"threat_level": r["threat_level"], "categories": list(r["categories"].keys()),
            "financial_targets": r["financial_targets"], "confidence": r["confidence"],
            "recommended_action": r["recommended_action"]}


@mcp.tool(annotations=ToolAnnotations(
    title="Feed sources & health",
    readOnlyHint=True, idempotentHint=True, openWorldHint=True))
async def feed_sources() -> dict:
    """List the public disclosure feeds this server aggregates, how many
    disclosures are cached per source, each source's newest item and an honest
    staleness flag, plus cache ages. Takes no arguments. Also states the scope
    plainly: public feeds only — no .onion access, no arbitrary fetching or
    crawling, no credential or PII output. Check this first if another tool's
    answer looks thin: a stale live feed is a finding, not background noise."""
    feed = await _feed()
    per: dict[str, dict] = {}
    for r in feed:
        b = per.setdefault(r["source"], {"cached": 0, "latest_item": ""})
        b["cached"] += 1
        if r.get("sort_date", "") > b["latest_item"]:
            b["latest_item"] = r["sort_date"]
    live_sources = {"HaveIBeenPwned", "RansomLook"}
    for name, b in per.items():
        b["stale"] = (name in live_sources
                      and _days_ago(b["latest_item"].replace(" ", "T")[:19] + "+00:00") > 21)
    sec_note = None
    if _SEC_STATE["total"] > _SEC_STATE["fetched"] and _SEC_STATE["fetched"]:
        sec_note = (f"SEC full-text search reports {_SEC_STATE['total']} Item 1.05 "
                    f"filings; {_SEC_STATE['fetched']} fetched (pagination cap).")
    return {
        "sources": [
            "HaveIBeenPwned — verified breach directory, 2007 → today (live)",
            "RansomLook — ransomware leak-site tracker (live)",
            "ransomwatch-archive — frozen leak-site archive, Jan 2020 → Jun 2025 "
            "(upstream stopped updating; retained as history)",
            "SEC EDGAR 8-K 1.05 — first-party material cyber-incident filings, "
            "Dec 2023 → today",
        ],
        "cached_disclosures": len(feed),
        "by_source": per,
        "sec_coverage_note": sec_note,
        "cache_age_seconds": {
            name.removeprefix("_fetch_"): (int(time.time() - slot["at"])
                                           if slot["at"] else None)
            for name, slot in _FEEDS.items()},
        "fetch_errors": dict(_LAST_ERRORS) or None,
        "scope": ("Public disclosure feeds only. No .onion access, no arbitrary "
                  "fetch/crawl, no credential or PII output."),
    }
