"""Lightweight, dependency-free threat classifier.

Keyword-based triage of security text into threat categories with a severity
level and a recommended action. Stdlib only, so the whole package stays tiny.
"""

from __future__ import annotations

import re

THREAT_CATEGORIES: dict[str, list[str]] = {
    "data_breach": [
        "data breach", "leaked database", "dump", "exposed data",
        "data leak", "compromised accounts", "stolen data",
    ],
    "ransomware": [
        "ransomware", "encrypted files", "ransom demand", "lockbit",
        "blackcat", "cl0p", "play ransomware", "data extortion",
        "double extortion",
    ],
    "credential_theft": [
        "credential dump", "password leak", "login credentials", "combo list",
        "stealer logs", "infostealer", "redline", "raccoon stealer", "vidar",
    ],
    "financial_fraud": [
        "banking trojan", "payment fraud", "card skimmer", "atm malware",
        "pos malware", "money mule", "business email compromise", "bec",
    ],
    "crypto_threat": [
        "wallet drain", "exchange hack", "rug pull", "flash loan attack",
        "bridge exploit", "smart contract exploit", "crypto scam", "ponzi",
        "exit scam",
    ],
    "insider_threat": [
        "insider trading", "insider threat", "data exfiltration",
        "corporate espionage", "trade secret",
    ],
    "supply_chain": [
        "supply chain attack", "dependency confusion", "malicious package",
        "compromised update",
    ],
    "sanctions_evasion": [
        "sanctions evasion", "money laundering", "kyc bypass", "mixer",
        "tornado cash", "ofac",
    ],
}

_TARGETS = re.compile(
    r"\b(bank|credit union|exchange|brokerage|insurance|fintech|"
    r"payment processor|clearing house|hedge fund|"
    r"jpmorgan|goldman sachs|morgan stanley|citibank|wells fargo|"
    r"binance|coinbase|kraken|bybit|okx|visa|mastercard|paypal|stripe)\b",
    re.I,
)


def classify_threat(text: str) -> dict:
    """Classify security text: threat level, categories, targets, action."""
    low = (text or "").lower()
    matched = {cat: [k for k in kws if k in low]
               for cat, kws in THREAT_CATEGORIES.items()}
    matched = {c: hits for c, hits in matched.items() if hits}
    targets = sorted({t.lower() for t in _TARGETS.findall(text or "")})

    n = len(matched)
    has_target = bool(targets)
    if n >= 3 or (n >= 2 and has_target):
        level, conf = "critical", 0.9
    elif n >= 2 or (n >= 1 and has_target):
        level, conf = "high", 0.75
    elif n >= 1:
        level, conf = "medium", 0.6
    else:
        level, conf = "low", 0.3

    action = {
        "critical": "IMMEDIATE: alert security, check exposure to affected entities",
        "high": "URGENT: review within the hour, assess exposure",
        "medium": "MONITOR: track for escalation",
        "low": "LOG: record for pattern analysis",
    }[level]

    return {
        "threat_level": level,
        "categories": matched,
        "financial_targets": targets,
        "confidence": conf,
        "recommended_action": action,
    }
