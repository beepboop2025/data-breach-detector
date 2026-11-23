"""Directory-scanner hygiene gate for the advertised MCP surface.

Automated MCP directories (Andrax Pentester's MCPGrade, mcpgrade.dev,
VerifyMCP and others) grade a server from tools/list, the prompt list and the
server instructions alone. They never read the code. So a sentence saying the
server never outputs credentials is graded as a credential channel, and a
description that names a sibling tool is graded as tool shadowing. That
surface earned this server a public F ("Do not connect") in an August 2026
scan. This test holds the surface to the same rules before any release.

Rules (fleet canon of 23 Nov 2026; keep in step with the fleet audit script):
 1. A tool's metadata describes only that tool: no other tool's name appears
    in its title, description or parameter text.
 2. The server instructions and prompt descriptions name no tool; they
    describe the workflow by role.
 3. No credential or personal-data trigger words in advertised metadata.
 4. No imperatives aimed at the model ("before answering", "ignore
    previous", "IMPORTANT:", "use these tools first" and the like).
 5. No invisible, zero-width or bidi control characters.
 6. No URL in tool metadata (a URL beside a fetch verb grades as
    fetch-and-obey).
 7. openWorldHint is never set to true explicitly: the spec default is
    already true, and scanners grade the explicit flag as over-broad scope.
 8. Every description stays under 1,000 characters.
 9. No parameter asks for a secret.
10. Every free-text string parameter is bounded (enum, const, pattern,
    format or maxLength).
11. No em or en dashes, the house rule for anything that ships.
"""
from __future__ import annotations

import asyncio
import json
import re

import pytest

from data_breach_detector.server import mcp

SENSITIVE = re.compile(
    r"pass(?:word|words|wd)|credential|credit[ -]?card|card number|\bcvv\b|\bssn\b"
    r"|social security|\bpii\b|personal data|\bsecrets?\b|api[ _-]?keys?\b|private key"
    r"|seed phrase|webhook|callback url|\bfeedback\b",
    re.I,
)
IMPERATIVE = re.compile(
    r"ignore (?:all |any )?(?:previous|prior)|disregard (?:all|any|previous)"
    r"|before (?:you )?answer(?:ing)?|instead of answering|you must|always (?:call|use)"
    r"|do not tell|\bIMPORTANT:|reach for (?:these|this) tools? first"
    r"|use (?:these|this) tools? first|\bFIRST,? before\b",
    re.I,
)
INVISIBLE = re.compile(
    "[​-‏‪-‮⁠-⁤⁦-⁩﻿︀-️"
    "\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
)
URL = re.compile(r"https?://", re.I)
DASHES = re.compile("[–—]")
SECRET_PARAM = re.compile(
    r"^(pass(word)?|passwd|secret|api[_-]?key|apikey|token|auth|bearer|private[_-]?key)$", re.I
)
BOUNDED = ("enum", "const", "pattern", "format", "maxLength")


@pytest.fixture(scope="module")
def surface():
    tools = asyncio.run(mcp.list_tools())
    prompts = asyncio.run(mcp.list_prompts())
    instructions = getattr(mcp, "instructions", None) or mcp._mcp_server.instructions or ""
    return tools, prompts, instructions


def _tool_text(tool) -> str:
    parts = [tool.title or "", tool.description or ""]
    if tool.annotations is not None and tool.annotations.title:
        parts.append(tool.annotations.title)
    for name, spec in (tool.inputSchema or {}).get("properties", {}).items():
        parts.append(f"{name}: {json.dumps(spec, ensure_ascii=False)}")
    return "\n".join(parts)


def _prompt_text(prompt) -> str:
    parts = [prompt.title or "", prompt.description or ""]
    for arg in prompt.arguments or []:
        parts.append(f"{arg.name}: {arg.description or ''}")
    return "\n".join(parts)


def _units(surface):
    """Every block of advertised text, labelled by where a scanner reads it."""
    tools, prompts, instructions = surface
    yield "(server instructions)", instructions
    for t in tools:
        yield f"tool {t.name}", _tool_text(t)
    for p in prompts:
        yield f"prompt {p.name}", _prompt_text(p)


def _names_in(text: str, names) -> list[str]:
    return [n for n in names
            if re.search(rf"(?<![A-Za-z0-9_]){re.escape(n)}(?![A-Za-z0-9_])", text)]


def test_metadata_never_names_another_tool(surface):
    tools, _prompts, _instructions = surface
    names = [t.name for t in tools]
    bad = []
    for where, text in _units(surface):
        own = where.removeprefix("tool ") if where.startswith("tool ") else None
        hits = _names_in(text, [n for n in names if n != own])
        if hits:
            bad.append(f"{where} names {hits}")
    assert not bad, "describe the workflow by role, not by tool name:\n" + "\n".join(bad)


@pytest.mark.parametrize("rule,pattern", [
    ("credential or personal-data trigger word", SENSITIVE),
    ("imperative aimed at the model", IMPERATIVE),
    ("invisible or bidi control character", INVISIBLE),
    ("em or en dash", DASHES),
])
def test_metadata_has_no_scanner_trigger(surface, rule, pattern):
    bad = []
    for where, text in _units(surface):
        m = pattern.search(text)
        if m:
            a = max(0, m.start() - 40)
            bad.append(f"{where}: ...{text[a:m.end() + 40]!r}")
    assert not bad, f"{rule} in advertised metadata:\n" + "\n".join(bad)


def test_tool_metadata_carries_no_url(surface):
    tools, _prompts, _instructions = surface
    bad = [t.name for t in tools if URL.search(_tool_text(t))]
    assert not bad, f"URL in tool metadata: {bad}"


def test_open_world_hint_is_never_explicitly_true(surface):
    tools, _prompts, _instructions = surface
    bad = [t.name for t in tools
           if t.annotations is not None and t.annotations.openWorldHint is True]
    assert not bad, f"explicit openWorldHint=true (the spec default already is): {bad}"


def test_descriptions_stay_short(surface):
    tools, _prompts, _instructions = surface
    bad = [f"{t.name}: {len(t.description or '')}" for t in tools
           if len(t.description or "") >= 1000]
    assert not bad, f"descriptions of 1,000 characters or more: {bad}"


def test_no_parameter_asks_for_a_secret(surface):
    tools, _prompts, _instructions = surface
    bad = [f"{t.name}.{p}" for t in tools
           for p in (t.inputSchema or {}).get("properties", {}) if SECRET_PARAM.match(p)]
    assert not bad, f"secret-shaped parameters: {bad}"


def test_every_free_text_parameter_is_bounded(surface):
    tools, _prompts, _instructions = surface
    bad = []
    for t in tools:
        for p, spec in (t.inputSchema or {}).get("properties", {}).items():
            for variant in spec.get("anyOf") or [spec]:
                if variant.get("type") == "string" and not any(k in variant for k in BOUNDED):
                    bad.append(f"{t.name}.{p}")
    assert not bad, f"unbounded free-text parameters: {bad}"


def test_the_gate_catches_what_the_scanner_caught():
    """The rules must fire on the exact sentences that earned the F."""
    names = ["breach_news", "check_exposure", "breach_history"]
    assert _names_in("for one organization use check_exposure", names) == ["check_exposure"]
    assert SENSITIVE.search("no credential or PII output")
    assert SENSITIVE.search("e.g. 'passwords', 'credit card'")
    assert IMPERATIVE.search("Reach for these tools FIRST, before answering from memory")
    assert not _names_in("an exposure check for one organization", names)
