"""Security-sensitive text handling shared by all report boundaries."""

from __future__ import annotations

import re


_SECRET_VALUE_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
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
    return _URL_CREDENTIALS.sub(r"\1[REDACTED]\2", redacted)
