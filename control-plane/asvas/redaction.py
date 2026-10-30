"""Secret redaction and untrusted-text handling (spec pp. 22, 26, 55, 74, 80).

Redaction is applied before anything is sent to an external model. It is best-effort pattern matching,
not a guarantee; the default provider is local and deterministic.
"""

from __future__ import annotations

import re

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL), "[REDACTED:private-key]"),
    (re.compile(r"(?i)\b(authorization|proxy-authorization)\s*[:=]\s*[^\r\n]+"), r"\1: [REDACTED]"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*"), "Bearer [REDACTED]"),
    (re.compile(r"(?i)\b(set-cookie|cookie)\s*[:=]\s*([^=;\s]+)=[^;\r\n]*"), r"\1: \2=[REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED:aws-key-id]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token|access[_-]?key)\b(\s*[:=]\s*)[^\s,;&\"']+"),
     r"\1\2[REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[REDACTED:jwt]"),
    (re.compile(r"\b(?:sk|pk|rk|ghp|gho|xox[abp])[-_][A-Za-z0-9_-]{16,}\b"), "[REDACTED:token]"),
]
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CTRL = re.compile("[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\u202a-\\u202e\\u2066-\\u2069]")


def redact(text: str, mask_ips: bool = False) -> str:
    out = text
    for pat, repl in _PATTERNS:
        out = pat.sub(repl, out)
    if mask_ips:
        out = _IPV4.sub("[IP]", out)
    return out


def untrusted_snippet(text: str | None, limit: int = 300) -> str | None:
    """Make target-controlled text safe to place in a *data* field: strip control/bidi chars, redact, truncate.

    This does not (and cannot) neutralise natural-language instructions; safety comes from the fact that
    nothing the model returns is executed without deterministic validation and policy checks.
    """
    if text is None:
        return None
    t = _CTRL.sub("", text)
    t = redact(t)
    return t[:limit] + ("…[truncated]" if len(t) > limit else "")
