"""Secret detection (regex + entropy) and redaction. Matches are never stored unredacted."""

from __future__ import annotations

import math
import re
from collections.abc import Iterator
from dataclasses import dataclass

# Provider-specific token shapes. Ordered: specific before generic. Patterns that need
# backtracking start only at a token boundary and have bounded repeats, so scanning stays linear
# on adversarial input (long runs of `sk-`, `eyJ`, identifier characters).
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("anthropic-api-key", re.compile(r"sk-ant-(?:api|admin|oat)\d{2}-[A-Za-z0-9_\-]{20,}")),
    (
        "openai-api-key",
        re.compile(
            r"(?<![A-Za-z0-9_\-])sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,256}T3BlbkFJ"
            r"[A-Za-z0-9_\-]{20,}"
        ),
    ),
    ("openai-style-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b")),
    (
        "github-token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    ),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b")),
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}\b")),
    ("stripe-key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{20,}\b")),
    ("huggingface-token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    (
        "jwt",
        re.compile(
            r"(?<![A-Za-z0-9_\-])eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"
        ),
    ),
)

# key = value assignments whose key names a secret; the value is tested for entropy. The key starts
# at an identifier boundary and is at most 128 characters (the secret word within its first 64),
# which keeps the scan linear on long identifier runs.
ASSIGNMENT = re.compile(
    r"""(?x)
    (?<![A-Za-z0-9_.\-])
    (?=[A-Za-z0-9_.\-]{0,64}?(?i:api[_\-]?key|secret|token|passw(?:or)?d|auth|credential|bearer))
    (?P<key>[A-Za-z0-9_.\-]{1,128})
    \s*["']?\s*[:=]\s*["']?
    (?P<value>[A-Za-z0-9+/_\-.=]{16,})
    """
)

PLACEHOLDER = re.compile(
    r"(?i)^(?:\$\{?[A-Z_][A-Z0-9_]*\}?|\$\{[^{}\s]+\}|<[^>]+>|x{6,}|\*{4,}|your[_\-].*|changeme|"
    r"example.*|dummy.*|placeholder.*|redacted.*|test[_\-]?key.*|\{\{.*\}\}|env:.*|op://.*)$"
)
# `${VAR:-default}`, `${env:VAR}`, `${input:id}` are all references, not values.


# URLs, paths, hostnames, emails and dotted identifiers are high-entropy but not secrets
# (embedded credentials in URLs are still caught by the provider patterns above).
NOT_A_TOKEN = re.compile(
    r"^(?:[a-z][a-z0-9+.\-]*://|[/~.]|[A-Za-z]:\\)|^[\w.\-]+@[\w.\-]+$|^(?:[\w\-]+\.){2,}[\w\-]+$"
)
# Package specifiers (`github:org/repo#<sha>`, `npm:pkg@1.0.0`) are not credentials either.
PACKAGE_SPEC = re.compile(r"^(?:github|gitlab|bitbucket|npm|jsr|file|workspace|git\+\w+):\S+$")

# Identifiers that are long and mixed but not secret by themselves: canonical UUIDs and
# separator-joined words/numbers such as model ids (`claude-sonnet-4-5-20250929`). They count as
# secrets only under a credential-named key (some providers do issue UUID-shaped API keys).
IDENTIFIER = re.compile(
    r"^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|(?:[A-Za-z]+|\d+)(?:[-_.](?:[A-Za-z]+|\d+))+)$"
)
SECRET_NAME = re.compile(
    r"(?i)api[_\-]?key|secret|token|passw(?:or)?d|credential|auth|private[_\-]?key"
)


@dataclass(frozen=True)
class SecretMatch:
    kind: str
    start: int
    end: int
    redacted: str


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {ch: text.count(ch) for ch in set(text)}
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


def redact(value: str) -> str:
    """Keep a short prefix (useful to identify the token type) and the length only."""
    keep = min(4, max(0, len(value) // 4))
    return f"{value[:keep]}…[redacted {len(value)} chars]"


def redact_text(text: str) -> str:
    """Replace every secret-shaped span in `text` with its redacted form."""
    spans = sorted(find_secrets(text), key=lambda m: m.start)
    out: list[str] = []
    last = 0
    for match in spans:
        if match.start < last:
            continue
        out += [text[last : match.start], match.redacted]
        last = match.end
    return "".join(out) + text[last:]


def looks_like_placeholder(value: str) -> bool:
    return bool(PLACEHOLDER.match(value.strip()))


def is_secret_value(value: str, min_entropy: float = 3.5, key: str | None = None) -> bool:
    """Heuristic for a bare value (env var, header): known shape, or long + high entropy.

    `key` is the name the value is stored under, when known; identifiers such as UUIDs and model
    ids are only treated as secrets under a credential-named key.
    """
    value = value.strip()
    if not value or looks_like_placeholder(value):
        return False
    if any(p.search(value) for _, p in SECRET_PATTERNS):
        return True
    token = value.split()[-1]  # "Bearer <token>"
    if looks_like_placeholder(token) or NOT_A_TOKEN.match(token) or PACKAGE_SPEC.match(token):
        return False
    if IDENTIFIER.match(token) and not (key and SECRET_NAME.search(key)):
        return False
    has_mix = any(c.isdigit() for c in token) and any(c.isalpha() for c in token)
    return len(token) >= 20 and has_mix and shannon_entropy(token) >= min_entropy


def find_secrets(text: str, min_entropy: float = 3.5) -> Iterator[SecretMatch]:
    """Yield secret-shaped spans in `text` (provider patterns, then key=value with entropy)."""
    taken: list[tuple[int, int]] = []
    for kind, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            if any(s <= m.start() < e for s, e in taken):
                continue
            taken.append((m.start(), m.end()))
            yield SecretMatch(kind, m.start(), m.end(), redact(m.group(0)))
    for m in ASSIGNMENT.finditer(text):
        start, end = m.span("value")
        value = m.group("value")
        if any(s <= start < e for s, e in taken) or looks_like_placeholder(value):
            continue
        has_mix = any(c.isdigit() for c in value) and any(c.isalpha() for c in value)
        if has_mix and not NOT_A_TOKEN.match(value) and shannon_entropy(value) >= min_entropy:
            taken.append((start, end))
            yield SecretMatch("high-entropy-assignment", start, end, redact(value))
