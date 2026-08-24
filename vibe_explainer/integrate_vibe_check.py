"""Optional loader for an existing vibe-check JSON report."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_vibe_check_report(path: str | Path) -> dict[str, Any] | None:
    """Load a vibe-check report if present and well-formed enough to use.

    Returns None on any failure so the explainer can still run offline.
    """
    p = Path(path)
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def summarize_vibe_findings(report: dict[str, Any]) -> list[str]:
    """Turn a vibe-check report into short risk notes for the explainer."""
    notes: list[str] = []
    summary = report.get("summary") or {}
    triage = report.get("triage") or report.get("disposition") or {}

    if isinstance(triage, dict):
        disposition = triage.get("disposition")
        if disposition:
            notes.append(f"vibe-check disposition: **{disposition}**")

    mapping = [
        ("syntax_errors", "syntax error(s) — treat as broken until fixed"),
        ("package_risks", "package risk(s) (undeclared imports / possible typosquats)"),
        ("duplicate_blocks", "duplicate code block(s) across files"),
        ("stubs", "stub / NotImplemented function(s)"),
        ("unreferenced_definitions", "unreferenced definition(s) (possible dead code)"),
        ("giant_files", "giant file(s) (>1000 lines)"),
        ("circular_imports", "circular import(s)"),
        ("comment_buzzwords", "comment buzzword hit(s)"),
    ]
    for key, label in mapping:
        n = summary.get(key)
        if isinstance(n, int) and n > 0:
            notes.append(f"{n} {label}")

    return notes
