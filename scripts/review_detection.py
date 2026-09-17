"""Evaluate a frozen corpus without changing detector rules or expected labels."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> int:
    from vibe_explainer.ai_discovery import discover_ai
    from vibe_explainer.attack_surface import build_attack_surface
    from vibe_explainer.dataflow import build_dataflow
    from vibe_explainer.controls import assess_controls
    from vibe_explainer.output import atomic_write_text
    from vibe_explainer.validation import evaluate_corpus
    corpus_path = ROOT / "validation" / "corpus.json"
    freeze_path = ROOT / "validation" / "beta-freeze.json"
    frozen_text = freeze_path.read_text(encoding="utf-8").replace("\r\n", "\n")
    if hashlib.sha256(frozen_text.encode()).hexdigest() != freeze_path.with_suffix(".sha256").read_text().strip():
        print("FAIL: supplemental evaluation changed after freeze")
        return 1
    freeze = json.loads(frozen_text)
    canonical = corpus_path.read_text(encoding="utf-8").replace("\r\n", "\n").encode()
    if hashlib.sha256(canonical).hexdigest() != freeze["corpus_sha256"]:
        print("FAIL: corpus changed after freeze; create a new review version")
        return 1
    report = evaluate_corpus(corpus_path)
    source_cases = {case["id"]: case for case in json.loads(corpus_path.read_text())["cases"]}
    for group, ids in freeze["partitions"].items():
        for case_id in ids:
            if json.loads((ROOT / "validation/frozen" / group / (case_id + ".json")).read_text()) != source_cases[case_id]:
                print(f"FAIL: frozen partition differs: {case_id}")
                return 1
    categories = {}
    observations = []
    with tempfile.TemporaryDirectory() as temp:
        for case in freeze["supplemental_cases"]:
            target = Path(temp) / case["id"]
            target.mkdir()
            for rel, source in case["files"].items():
                path = target / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source, encoding="utf-8")
            discovery = discover_ai(target)
            surface = build_attack_surface(discovery)
            controls = assess_controls(discovery, surface, build_dataflow(discovery))
            observed = {f.category for f in discovery.conclusion_findings()}
            observed.update(c.control_id for c in controls.controls if c.evidence)
            for signal, expected in case["labels"].items():
                found = signal in observed
                metric = categories.setdefault(signal, {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
                metric[("tp" if found else "fn") if expected else ("fp" if found else "tn")] += 1
                observations.append({"fixture": case["id"], "signal": signal, "expected": expected, "observed": found,
                                     "mismatch": found != expected, "fixed": False})
    for metric in categories.values():
        metric["precision"] = metric["tp"] / (metric["tp"] + metric["fp"]) if metric["tp"] + metric["fp"] else None
        metric["recall"] = metric["tp"] / (metric["tp"] + metric["fn"]) if metric["tp"] + metric["fn"] else None
    result = {"review_status": "PENDING_INDEPENDENT_REVIEW", "frozen_corpus": report,
              "supplemental_by_signal": categories, "error_analysis": observations,
              "note": "Small implementation-authored corpus; descriptive detector metrics only. No statistical or control-effectiveness claims."}
    output = ROOT / "validation" / "beta-review-metrics.json"
    atomic_write_text(output, json.dumps(result, indent=2, sort_keys=True) + "\n", overwrite=True)
    print(json.dumps({"corpus": report["overall"], "supplemental": categories}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
