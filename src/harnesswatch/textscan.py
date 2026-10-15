"""Injection-indicator scanning for instruction files, rules, skills and MCP tool descriptions.

Scored, not binary: each indicator carries a weight; the total drives severity.

Every scanner is linear in the input: line numbers come from one precomputed newline index, and
patterns that could backtrack are bounded or possessive (files are untrusted, up to a few MB).
"""

from __future__ import annotations

import re
import unicodedata
from bisect import bisect_right
from collections.abc import Callable, Iterator
from dataclasses import dataclass

ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF, 0x180E}
BIDI = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F}


def _hidden_kind(cp: int) -> str | None:
    if cp in ZERO_WIDTH:
        return "zero-width"
    if cp in BIDI:
        return "bidi-control"
    if 0xE0000 <= cp <= 0xE007F:
        return "unicode-tag"  # "ASCII smuggling"
    if 0xE0100 <= cp <= 0xE01EF:
        return "variation-selector-supplement"
    if 0xFFF9 <= cp <= 0xFFFB:
        return "interlinear-annotation"
    return None


@dataclass(frozen=True)
class Indicator:
    kind: str
    line: int
    weight: int
    detail: str


@dataclass(frozen=True)
class Phrase:
    kind: str
    weight: int
    pattern: re.Pattern[str]


def _p(kind: str, weight: int, regex: str) -> Phrase:
    return Phrase(kind, weight, re.compile(regex, re.IGNORECASE))


PHRASES: tuple[Phrase, ...] = (
    _p(
        "override",
        4,
        r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|"
        r"all|any|other|system)\b[^.\n]{0,20}\b(?:instructions?|rules?|prompts?|guidelines?)",
    ),
    _p(
        "concealment",
        4,
        r"\b(?:do not|don't|never|without)\b[^.\n]{0,20}\b(?:tell|inform|mention|notify|alert|"
        r"reveal|show|ask(?:ing)?)\b[^.\n]{0,15}\b(?:the user|user|human|anyone|them)",
    ),
    _p(
        "concealment",
        3,
        r"\b(?:silently|secretly|covertly|quietly)\b[^.\n]{0,40}\b(?:run|execute|send|upload|read|add|insert|modify)",
    ),
    _p(
        "role-play",
        2,
        r"\byou are (?:now|no longer)\b|\bnew (?:system )?instructions?\b|\bact as (?:an? )?(?:unrestricted|jailbroken|DAN)",
    ),
    _p(
        "fake-authority",
        2,
        r"\b(?:system|admin(?:istrator)?|developer|security team)\s*(?:override|message|notice|instruction)s?\s*:",
    ),
    _p(
        "secret-access",
        2,
        r"(?:~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.netrc|\.npmrc|\.pypirc|\.env\b|"
        r"\.claude/\.credentials|auth\.json|\bAPI[_ ]?KEYS?\b|\bprivate key\b|\bcredentials?\b)",
    ),
    _p(
        "exfiltration",
        4,
        r"\b(?:send|post|upload|exfiltrate|transmit|forward|leak|beacon)\b[^\n]{0,60}?"
        r"(?:https?://|\bto (?:this|the following|my) (?:url|endpoint|server|webhook))",
    ),
    _p(
        "pipe-to-shell",
        4,
        r"(?:curl|wget|iwr|Invoke-WebRequest)\b[^|\n]{0,200}\|\s*(?:ba|z)?sh\b|base64\s+-d[^|\n]{0,200}\|\s*(?:ba|z)?sh",
    ),
    _p(
        "auto-approve",
        3,
        r"--dangerously-skip-permissions|--yolo\b|--full-auto|bypassPermissions|auto[_ -]?approve|dangerouslyAllowAll",
    ),
    _p(
        "tool-shadowing",
        3,
        r"\b(?:before|instead of|whenever you)\b[^.\n]{0,30}\b(?:using|calling|call|use)\b[^.\n]{0,30}\btool\b",
    ),
    _p(
        "markdown-exfil",
        3,
        r"!\[[^\]\[\n]*+\]\(https?://[^)\s\[]*?(?:\{|\$|%7B|\?[^)\s\[?=]*+=)",
    ),
)

BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/])")
HEX_BLOB = re.compile(r"\b(?:[0-9a-fA-F]{2}){48,}\b")
URL = re.compile(r"https?://[^\s)>\]\"']+")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
REMOTE_IMPORT = re.compile(
    r"(?im)^[ \t]*(?:@https?://|!include\s+https?://|import\s+https?://)"
    r"|\b(?:fetch|load|read|download|curl|wget)\b[^.\n]{0,40}\b(?:instructions?|rules?|prompt|guidelines?)\b"
    r"[^.\n]{0,40}https?://"
    r"|\b(?:instructions?|rules?|prompt|guidelines?)\b[^.\n]{0,30}\bfrom\b[^.\n]{0,20}https?://"
)


def line_index(text: str) -> Callable[[int], int]:
    """Return `index -> line number` for `text`, built once (O(log n) per lookup)."""
    newlines = [m.start() for m in re.finditer("\n", text)]
    return lambda index: bisect_right(newlines, index - 1) + 1


def _html_comments(text: str) -> Iterator[tuple[int, str]]:
    """`<!-- ... -->` comments as (start, body), found with str.find (a lazy regex is quadratic)."""
    start = text.find("<!--")
    while start >= 0:
        end = text.find("-->", start + 4)
        if end < 0:
            return
        yield start, text[start + 4 : end]
        start = text.find("<!--", end + 3)


def _is_pictographic(char: str) -> bool:
    return ord(char) >= 0x1F000 or unicodedata.category(char) in {"So", "Sk"} or char == "\ufe0f"


def _benign(text: str, index: int, kind: str) -> bool:
    """Legitimate uses: BOM at start, ZWJ inside emoji sequences, emoji subdivision flags."""
    cp = ord(text[index])
    if cp == 0xFEFF and index == 0:
        return True
    if cp == 0x200D and 0 < index < len(text) - 1:
        return _is_pictographic(text[index - 1]) and _is_pictographic(text[index + 1])
    if kind == "unicode-tag":  # a flag is at most 7 tags long: look no further than 8 each way
        start = index
        while start > max(0, index - 8) and 0xE0000 <= ord(text[start - 1]) <= 0xE007F:
            start -= 1
        end = index
        while end < min(len(text) - 1, index + 8) and 0xE0000 <= ord(text[end + 1]) <= 0xE007F:
            end += 1
        flag = start > 0 and ord(text[start - 1]) == 0x1F3F4 and ord(text[end]) == 0xE007F
        return flag and end - start <= 7
    return False


def hidden_unicode(text: str) -> list[Indicator]:
    found: dict[tuple[str, int], int] = {}
    lines = line_index(text)
    for index, char in enumerate(text):
        kind = _hidden_kind(ord(char))
        if kind and not _benign(text, index, kind):
            key = (kind, lines(index))
            found[key] = found.get(key, 0) + 1
    out = [
        Indicator(kind, line, 5 if kind in {"unicode-tag", "bidi-control"} else 3, f"{n}x {kind}")
        for (kind, line), n in found.items()
    ]
    out.extend(_mixed_script(text, lines))
    return sorted(out, key=lambda i: i.line)


_WORD = re.compile(r"\w{3,}")
# SI quantities written with the Greek mu or omega (`10μm`, `5μs`, `47kΩ`) mix scripts legitimately.
_UNIT = re.compile(r"^\d+[kMGmμ]?[μΩ]?[A-Za-z]{0,3}$")


def _script(char: str) -> str | None:
    if not char.isalpha():
        return None
    name = unicodedata.name(char, "")
    for script in ("LATIN", "CYRILLIC", "GREEK"):
        if name.startswith(script):
            return script
    return "OTHER"


def _mixed_script(text: str, lines: Callable[[int], int]) -> list[Indicator]:
    """Words mixing Latin with Cyrillic/Greek letters (homoglyph confusables)."""
    out = []
    for m in _WORD.finditer(text):
        scripts = {s for s in map(_script, m.group(0)) if s}
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"} and not _UNIT.match(m.group(0)):
            out.append(
                Indicator(
                    "confusable",
                    lines(m.start()),
                    3,
                    f"mixed-script word at col {m.start()}",
                )
            )
    return out


# A command quoted as something *not* to do ("Never pipe … `curl … | sh`") is guidance, not intent.
PROHIBITED = re.compile(
    r"\b(?:never|don't|do not|must not|mustn't|should not|shouldn't|avoid|forbidden|prohibited)\b",
    re.IGNORECASE,
)
NEGATABLE_KINDS = frozenset({"pipe-to-shell"})


def _prohibited(text: str, start: int) -> bool:
    """True when the sentence leading up to `start` (same line) forbids the action."""
    line_start = max(text.rfind("\n", 0, start) + 1, start - 500)
    sentence = re.split(r"[.!?;]\s", text[line_start:start])[-1]
    return bool(PROHIBITED.search(sentence))


def phrase_indicators(text: str) -> list[Indicator]:
    out = []
    lines = line_index(text)
    for phrase in PHRASES:
        for m in phrase.pattern.finditer(text):
            if phrase.kind in NEGATABLE_KINDS and _prohibited(text, m.start()):
                continue
            out.append(Indicator(phrase.kind, lines(m.start()), phrase.weight, m.group(0)[:80]))
    for start, body in _html_comments(text):
        inner = phrase_indicators(body) if body.strip() else []
        weight = 2 + (2 if inner else 0)
        if len(body.strip()) > 20:
            out.append(Indicator("html-comment", lines(start), weight, body.strip()[:60]))
    for m in BASE64_BLOB.finditer(text):
        out.append(
            Indicator("encoded-blob", lines(m.start()), 2, f"base64-like, {len(m.group(0))} chars")
        )
    for m in HEX_BLOB.finditer(text):
        out.append(Indicator("encoded-blob", lines(m.start()), 2, f"hex, {len(m.group(0))} chars"))
    return out


# "rules adapted from https://…" credits a source; it does not tell the agent to load it.
ATTRIBUTION = re.compile(
    r"\b(?:adapted|derived|based on|taken|copied|inspired|borrowed|forked|ported|translated)\s+from\b",
    re.IGNORECASE,
)


def remote_imports(text: str) -> list[Indicator]:
    lines = line_index(text)
    return [
        Indicator("remote-content", lines(m.start()), 3, m.group(0).strip()[:80])
        for m in REMOTE_IMPORT.finditer(text)
        if not ATTRIBUTION.search(m.group(0))
    ]


def endpoints(text: str) -> list[Indicator]:
    lines = line_index(text)
    out = [Indicator("url", lines(m.start()), 0, m.group(0)[:80]) for m in URL.finditer(text)]
    for m in IPV4.finditer(text):
        if all(0 <= int(o) <= 255 for o in m.group(0).split(".")) and not m.group(0).startswith(
            ("0.", "127.")
        ):
            out.append(Indicator("ip-address", lines(m.start()), 1, m.group(0)))
    return out


# Indicators that express intent to act against the user; weak ones only add context.
STRONG_KINDS = frozenset(
    {
        "override",
        "concealment",
        "exfiltration",
        "pipe-to-shell",
        "fake-authority",
        "tool-shadowing",
        "markdown-exfil",
        "unicode-tag",
        "bidi-control",
    }
)


def score(indicators: list[Indicator]) -> int:
    """Sum of the highest weight per indicator kind (repeats of one kind do not stack)."""
    best: dict[str, int] = {}
    for indicator in indicators:
        best[indicator.kind] = max(best.get(indicator.kind, 0), indicator.weight)
    return sum(best.values())


def has_strong(indicators: list[Indicator]) -> bool:
    return any(i.kind in STRONG_KINDS for i in indicators)
