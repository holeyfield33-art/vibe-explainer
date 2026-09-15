"""Security-sensitive text handling shared by all report boundaries."""

from __future__ import annotations

import re
from typing import Any


_SECRET_VALUE_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bSG\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
)

_SENSITIVE_ASSIGNMENT = re.compile(
    # The identifier prefix is optional (zero-or-more, not one-or-more) so a bare
    # keyword such as ``PASSWORD = "..."`` or ``TOKEN = "..."`` is redacted, not just
    # prefixed forms like ``MY_PASSWORD``/``DB_TOKEN``.
    r"(?i)(\b(?:[A-Za-z_][A-Za-z0-9_]*)?(?:API[_-]?KEY|ACCESS[_-]?KEY|TOKEN|SECRET|PASSWORD|PRIVATE[_-]?KEY)"
    r"\b\s*[:=]\s*)([^\s,;}]+|[\"'][^\"']*[\"'])"
)

# The password run allows ``@`` and is greedy up to the LAST ``@`` before the
# host/path boundary (``/`` or whitespace ends the authority component), so a
# password containing embedded ``@`` (e.g. ``user:Sup3r@Secret@host/db``) is
# redacted in full rather than only up to the first ``@``.
_URL_CREDENTIALS = re.compile(r"(?i)([a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s/]+(@)")

_STRUCTURED_SECRET = re.compile(
    r"(?i)((?:[\"']?)(?:password|passwd|pwd|client[_-]?secret|account[_-]?key|"
    r"shared[_-]?access[_-]?key|secret[_-]?access[_-]?key)(?:[\"']?)\s*[:=]\s*)"
    r"([\"']?)[^\s,;}\"']+\2"
)


def redact_secrets(text: str) -> str:
    """Redact common credential values while retaining useful source context.

    This is deliberately defense-in-depth, not a claim that every possible secret
    format can be recognized. Key-name assignments are redacted even for unknown
    provider formats so evidence lines do not reproduce their values.
    """
    redacted = text
    for pattern in _SECRET_VALUE_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    redacted = _SENSITIVE_ASSIGNMENT.sub(r"\1[REDACTED]", redacted)
    redacted = _STRUCTURED_SECRET.sub(r"\1[REDACTED]", redacted)
    return _URL_CREDENTIALS.sub(r"\1[REDACTED]\2", redacted)


def minimal_match_excerpt(text: str, start: int, end: int, *, context_chars: int = 24) -> str:
    """Return a bounded, single-line excerpt around a match, never a full line."""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)
    raw_line = text[line_start:line_end]
    redacted_line = redact_secrets(raw_line)
    match_text = redact_secrets(text[start:end])
    # Locate after redacting the complete line so a context boundary can never
    # retain a truncated fragment of an otherwise recognizable credential.
    match_offset = redacted_line.find(match_text)
    if match_offset < 0:
        return match_text[:96]
    excerpt_start = max(0, match_offset - context_chars)
    excerpt_end = min(len(redacted_line), match_offset + len(match_text) + context_chars)
    marker = "[REDACTED]"
    for marker_start in (m.start() for m in re.finditer(re.escape(marker), redacted_line)):
        marker_end = marker_start + len(marker)
        if marker_start < excerpt_end < marker_end:
            excerpt_end = marker_end
        if marker_start < excerpt_start < marker_end:
            excerpt_start = marker_start
    prefix = "…" if excerpt_start > 0 else ""
    suffix = "…" if excerpt_end < len(redacted_line) else ""
    return prefix + redacted_line[excerpt_start:excerpt_end].strip() + suffix


def redact_structure(value: Any) -> Any:
    """Recursively apply the shared redactor at serialization boundaries."""
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, dict):
        return {key: redact_structure(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_structure(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_structure(item) for item in value)
    return value
