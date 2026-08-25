"""Finding context classification.

The red-team review of the first real-world run (aletheia-core) found that discovery
is accurate but the report couldn't distinguish a single production webhook from 30
test-fixture / manifest / documentation matches of the same string. The fix it
recommended was NOT more detection regexes — it was a context layer:

    Finding -> Production | Test | Example | Documentation | Generated -> risk weighting

This module is that layer. It classifies an already-discovered finding by its file
path alone (plus a couple of cheap filename signals). It adds NO new detection, does
not re-scan, and does not change any finding's identity, evidence, or confidence — it
only annotates *where the evidence lives*, so the report and risk layers can weight a
production finding above a test fixture.

Deliberately path-based and small: the point is context, not a second scanner.
"""

from __future__ import annotations

import re

CONTEXT_PRODUCTION = "PRODUCTION"
CONTEXT_TEST = "TEST"
CONTEXT_EXAMPLE = "EXAMPLE"
CONTEXT_DOCUMENTATION = "DOCUMENTATION"
CONTEXT_GENERATED = "GENERATED"

# Ordered most-specific to least; first match wins. Each entry is (context, regex)
# matched case-insensitively against the POSIX-style relative path.
_RULES: list[tuple[str, re.Pattern[str]]] = [
    # Tests: a tests dir at any depth, or a test_*/*_test filename, or spec files.
    (CONTEXT_TEST, re.compile(r"(^|/)tests?(/|$)|(^|/)__tests__(/|$)|(^|/)(test_[^/]+|[^/]+_test)\.[a-z]+$|(^|/)[^/]+\.(spec|test)\.[a-z]+$", re.IGNORECASE)),
    # Examples / demos / fixtures / samples.
    (CONTEXT_EXAMPLE, re.compile(r"(^|/)(examples?|demos?|samples?|fixtures?)(/|$)|(^|/)demo[_-]|[_-]demo\.[a-z]+$", re.IGNORECASE)),
    # Documentation: docs dirs, markdown/rst/txt anywhere.
    (CONTEXT_DOCUMENTATION, re.compile(r"(^|/)docs?(/|$)|\.(md|mdx|rst|txt)$", re.IGNORECASE)),
    # Generated / build / vendored / infra manifests: lock files, build output,
    # generated graphs/manifests, helm/k8s templates, node_modules-style vendor.
    (CONTEXT_GENERATED, re.compile(
        r"(^|/)(dist|build|out|coverage|node_modules|vendor|\.next|target)(/|$)"
        r"|(^|/)charts?(/|$)"
        r"|(^|/)[^/]*(manifest|graph-ts|graph)\.json$"
        r"|(^|/)[^/]+\.(lock|min\.js|generated\.[a-z]+)$"
        r"|(^|/)package-lock\.json$|(^|/)yarn\.lock$|(^|/)poetry\.lock$",
        re.IGNORECASE,
    )),
]


def classify_path(rel_path: str) -> str:
    """Classify a repository-relative path into one context bucket.

    Anything not matching a test/example/doc/generated signal is treated as
    PRODUCTION — the conservative default, since an unrecognized path is more
    dangerous to under-weight than to over-weight.
    """
    normalized = rel_path.replace("\\", "/")
    for context, pattern in _RULES:
        if pattern.search(normalized):
            return context
    return CONTEXT_PRODUCTION


# Weight applied to a finding's contribution when the report/risk layers want to
# emphasize production surface. Not used to alter Phase 5 scores (that formula is
# fixed); used only for report emphasis / ordering. Production is full weight;
# everything else is de-emphasized to varying degrees.
CONTEXT_WEIGHT = {
    CONTEXT_PRODUCTION: 1.0,
    CONTEXT_TEST: 0.2,
    CONTEXT_EXAMPLE: 0.15,
    CONTEXT_DOCUMENTATION: 0.1,
    CONTEXT_GENERATED: 0.1,
}


def is_production(rel_path: str) -> bool:
    return classify_path(rel_path) == CONTEXT_PRODUCTION
