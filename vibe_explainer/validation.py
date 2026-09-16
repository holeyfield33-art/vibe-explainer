"""Offline multi-axis quality benchmark for the checked-in labelled corpus."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from .ai_discovery import AIFinding, discover_ai
from .dataflow import build_dataflow

DEFAULT_CORPUS = Path(__file__).resolve().parents[1] / "validation" / "corpus.json"
PYTHON_PRECISION_MINIMUM = 0.90


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def _axis(rows: list[dict[str, Any]], applicable: str, passed: str) -> dict[str, Any]:
    selected = [row for row in rows if row[applicable]]
    correct = sum(bool(row[passed]) for row in selected)
    return {"cases": len(selected), "correct": correct, "accuracy": _ratio(correct, len(selected))}


def _metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    tp = sum(r["expected"] == "authoritative" and r["actual"] == "authoritative" for r in rows)
    fp = sum(r["expected"] != "authoritative" and r["actual"] == "authoritative" for r in rows)
    fn = sum(r["expected"] == "authoritative" and r["actual"] != "authoritative" for r in rows)
    tn = len(rows) - tp - fp - fn
    return {
        "cases": len(rows),
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
        "authoritative_precision": _ratio(tp, tp + fp),
        "authoritative_recall": _ratio(tp, tp + fn),
        "unsupported_rate": _ratio(sum(r["actual"] == "unsupported" for r in rows), len(rows)),
        "unresolved_rate": _ratio(sum(r["actual"] == "unresolved" for r in rows), len(rows)),
        "disposition_accuracy": _ratio(sum(r["disposition_pass"] for r in rows), len(rows)),
        "finding_identity": _axis(rows, "finding_identity_applicable", "finding_identity_pass"),
        "context": _axis(rows, "context_applicable", "context_pass"),
        "relationship": _axis(rows, "relationship_applicable", "relationship_pass"),
    }


def _matches_finding(finding: AIFinding, expected: dict[str, Any]) -> bool:
    return all(getattr(finding, key, None) == value for key, value in expected.items())


def _matches_relationship(edge: dict[str, Any], expected: dict[str, Any]) -> bool:
    return all(edge.get(key) == value for key, value in expected.items())


def _actual_disposition(findings: list[AIFinding]) -> str:
    if any(f.supports_conclusions for f in findings):
        return "authoritative"
    if any(f.evidence_basis.startswith("UNRESOLVED_") for f in findings):
        return "unresolved"
    if any(f.evidence_basis == "LEXICAL_LEAD" for f in findings):
        return "unsupported"
    return "none"


def evaluate_corpus(corpus_path: str | Path = DEFAULT_CORPUS) -> dict[str, Any]:
    corpus = json.loads(Path(corpus_path).read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="vibe-explainer-corpus-") as root:
        root_path = Path(root)
        for case in corpus["cases"]:
            case_root = root_path / case["id"]
            files = case.get("files") or [{"path": case["path"], "source": case["source"]}]
            for file in files:
                target = case_root / file["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(file["source"], encoding="utf-8")
            discovery = discover_ai(case_root)
            authoritative = discovery.conclusion_findings()
            actual = _actual_disposition(discovery.findings)
            expected_findings = case.get("expected_findings", [])
            finding_pass = all(
                any(_matches_finding(finding, expected) for finding in authoritative)
                for expected in expected_findings
            )
            expected_context = case.get("expected_context")
            context_candidates = authoritative
            if expected_findings:
                context_candidates = [
                    finding for finding in authoritative
                    if any(_matches_finding(finding, expected) for expected in expected_findings)
                ]
            context_pass = (
                any(finding.context == expected_context for finding in context_candidates)
                if expected_context is not None else True
            )
            expected_relationships = case.get("expected_relationships", [])
            edges = [edge.to_dict() for edge in build_dataflow(discovery).edges]
            relationship_pass = all(
                any(_matches_relationship(edge, expected) for edge in edges)
                for expected in expected_relationships
            )
            disposition_pass = actual == case["expected"]
            passed = disposition_pass and finding_pass and context_pass and relationship_pass
            rows.append({
                "id": case["id"],
                "language": case["language"],
                "construct": case["construct"],
                "expected": case["expected"],
                "actual": actual,
                "mandatory": case.get("mandatory", True),
                "known_limitation": bool(case.get("known_limitation", False)),
                "disposition_pass": disposition_pass,
                "finding_identity_applicable": bool(expected_findings),
                "finding_identity_pass": finding_pass,
                "context_applicable": expected_context is not None,
                "context_pass": context_pass,
                "relationship_applicable": bool(expected_relationships),
                "relationship_pass": relationship_pass,
                "passed": passed,
            })
    by_language: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_construct: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_language[row["language"]].append(row)
        by_construct[row["construct"]].append(row)
    return {
        "schema_version": "2.0",
        "corpus_version": corpus["version"],
        "label_review": corpus["label_review"],
        "metric_gate": {"python_authoritative_precision_minimum": PYTHON_PRECISION_MINIMUM},
        "overall": _metrics(rows),
        "by_language": {key: _metrics(value) for key, value in sorted(by_language.items())},
        "by_construct": {key: _metrics(value) for key, value in sorted(by_construct.items())},
        "mandatory_mismatches": [row["id"] for row in rows if row["mandatory"] and not row["passed"]],
        "known_mismatches": [row["id"] for row in rows if row["known_limitation"] and not row["passed"]],
        "cases": rows,
    }


def metric_gate_passes(report: dict[str, Any]) -> bool:
    precision = report["by_language"].get("python", {}).get("authoritative_precision")
    return precision is not None and precision >= PYTHON_PRECISION_MINIMUM


def _print_mismatches(report: dict[str, Any]) -> None:
    for case in report["cases"]:
        if case["passed"]:
            continue
        label = "KNOWN BENCHMARK FALSE NEGATIVE" if case["known_limitation"] else "FAIL"
        print(f"{label} {case['id']}", file=sys.stderr)
        print(f"  expected: {case['expected']}", file=sys.stderr)
        print(f"  actual: {case['actual']}", file=sys.stderr)
        for axis in ("finding_identity", "context", "relationship"):
            if case[f"{axis}_applicable"] and not case[f"{axis}_pass"]:
                print(f"  {axis}: mismatch", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--metrics-gate", action="store_true", help="enforce documented aggregate thresholds")
    parser.add_argument("--check", "--exact-labels", dest="exact_labels", action="store_true", help="fail on any mandatory label or axis mismatch")
    args = parser.parse_args(argv)
    report = evaluate_corpus(args.corpus)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    _print_mismatches(report)
    failed = False
    if args.metrics_gate and not metric_gate_passes(report):
        print("FAIL metric gate: Python authoritative precision is below 0.90", file=sys.stderr)
        failed = True
    if args.exact_labels and report["mandatory_mismatches"]:
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
