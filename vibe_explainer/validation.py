"""Offline detection-quality benchmark for the checked-in labelled corpus."""

from __future__ import annotations

import argparse
import json
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from .ai_discovery import discover_ai

DEFAULT_CORPUS = Path(__file__).resolve().parents[1] / "validation" / "corpus.json"


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


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
        "precision": _ratio(tp, tp + fp),
        "recall": _ratio(tp, tp + fn),
        "unsupported_rate": _ratio(sum(r["actual"] == "unsupported" for r in rows), len(rows)),
        "unresolved_rate": _ratio(sum(r["actual"] == "unresolved" for r in rows), len(rows)),
        "disposition_accuracy": _ratio(sum(r["expected"] == r["actual"] for r in rows), len(rows)),
    }


def evaluate_corpus(corpus_path: str | Path = DEFAULT_CORPUS) -> dict[str, Any]:
    corpus = json.loads(Path(corpus_path).read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="vibe-explainer-corpus-") as root:
        root_path = Path(root)
        for case in corpus["cases"]:
            case_root = root_path / case["id"]
            files = case.get("files", [{"path": case["path"], "source": case["source"]}])
            for file in files:
                target = case_root / file["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(file["source"], encoding="utf-8")
            result = discover_ai(case_root)
            if result.conclusion_findings():
                actual = "authoritative"
            elif any(f.evidence_basis.startswith("UNRESOLVED_") for f in result.findings):
                actual = "unresolved"
            elif any(f.evidence_basis == "LEXICAL_LEAD" for f in result.findings):
                actual = "unsupported"
            else:
                actual = "none"
            rows.append({
                "id": case["id"],
                "language": case["language"],
                "construct": case["construct"],
                "expected": case["expected"],
                "actual": actual,
                "passed": actual == case["expected"],
            })

    by_language: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_construct: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_language[row["language"]].append(row)
        by_construct[row["construct"]].append(row)
    return {
        "schema_version": "1.0",
        "corpus_version": corpus["version"],
        "label_review": corpus["label_review"],
        "overall": _metrics(rows),
        "by_language": {key: _metrics(value) for key, value in sorted(by_language.items())},
        "by_construct": {key: _metrics(value) for key, value in sorted(by_construct.items())},
        "cases": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true", help="fail if a labelled disposition differs")
    args = parser.parse_args(argv)
    report = evaluate_corpus(args.corpus)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    python_precision = report["by_language"].get("python", {}).get("precision")
    meets_gate = python_precision is not None and python_precision >= 0.9
    return 1 if args.check and not meets_gate else 0


if __name__ == "__main__":
    raise SystemExit(main())
