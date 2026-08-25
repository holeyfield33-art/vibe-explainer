"""Backward-compatibility shim.

Phase 8 introduced the richer file_context.py taxonomy (11 contexts, multi-signal,
confidence + reasons). This module preserves the original 5-value classify_path()
API that Phase 7 code and tests use, mapping the new contexts down to the original
coarse set so existing behavior is unchanged.
"""

from __future__ import annotations

from .file_context import (
    CONTEXT_DEMO,
    CONTEXT_DOCUMENTATION,
    CONTEXT_EXAMPLE,
    CONTEXT_FIXTURE,
    CONTEXT_GENERATED,
    CONTEXT_SECURITY_TEST,
    CONTEXT_TEST,
    CONTEXT_VENDOR,
    classify_file,
)

# Original coarse contexts (Phase 7 contract).
CONTEXT_PRODUCTION = "PRODUCTION"
CONTEXT_TEST = "TEST"
CONTEXT_EXAMPLE = "EXAMPLE"
CONTEXT_DOCUMENTATION = "DOCUMENTATION"
CONTEXT_GENERATED = "GENERATED"

# Map the fine-grained Phase 8 taxonomy down to the coarse Phase 7 set.
_COARSE = {
    "PRODUCTION": CONTEXT_PRODUCTION,
    "CONFIGURATION": CONTEXT_PRODUCTION,
    "UNKNOWN": CONTEXT_PRODUCTION,
    "TEST": CONTEXT_TEST,
    "SECURITY_TEST": CONTEXT_TEST,
    "FIXTURE": CONTEXT_TEST,
    "EXAMPLE": CONTEXT_EXAMPLE,
    "DEMO": CONTEXT_EXAMPLE,
    "DOCUMENTATION": CONTEXT_DOCUMENTATION,
    "GENERATED": CONTEXT_GENERATED,
    "VENDOR": CONTEXT_GENERATED,
}

CONTEXT_WEIGHT = {
    CONTEXT_PRODUCTION: 1.0,
    CONTEXT_TEST: 0.2,
    CONTEXT_EXAMPLE: 0.15,
    CONTEXT_DOCUMENTATION: 0.1,
    CONTEXT_GENERATED: 0.1,
}


def classify_path(rel_path: str) -> str:
    """Coarse 5-value classification (backward-compatible Phase 7 API)."""
    fine = classify_file(rel_path).context
    return _COARSE.get(fine, CONTEXT_PRODUCTION)


def is_production(rel_path: str) -> bool:
    return classify_path(rel_path) == CONTEXT_PRODUCTION
