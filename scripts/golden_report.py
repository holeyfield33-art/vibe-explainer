"""Render/check the frozen analyst candidate. Approval is a separate human gate."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
FIXTURE = ROOT / "examples" / "analyst-review-fixture"
GOLDEN = ROOT / "examples" / "sample-assessment" / "beta-golden.md"


def fixture_hash() -> str:
    digest = hashlib.sha256()
    for file in sorted(FIXTURE.rglob("*")):
        if file.is_file() and "__pycache__" not in file.parts:
            digest.update(file.relative_to(FIXTURE).as_posix().encode() + b"\0")
            digest.update(file.read_text(encoding="utf-8").replace("\r\n", "\n").encode())
    return digest.hexdigest()


def render() -> str:
    import tempfile
    from vibe_explainer.cli import main
    from vibe_explainer.security_report import VibeExplainerReport
    from vibe_explainer.consultant_report import render_consultant_markdown

    with tempfile.TemporaryDirectory() as temp:
        output = Path(temp) / "review.json"
        assert main([str(FIXTURE), "--json", "--out", str(output)]) == 0
        payload = json.loads(output.read_text(encoding="utf-8"))
    payload.pop("assessment_manifest")
    report = VibeExplainerReport(**payload)
    # Only operational metadata is normalized, never findings or conclusions.
    report.metadata["repository_path"] = "examples/analyst-review-fixture"
    report.metadata["repository_revision"] = {"commit": None, "branch": None, "dirty": None, "available": False}
    report.metadata["scan_scope"]["elapsed_seconds"] = "measured at runtime; omitted from golden comparison"
    report.metadata["scan_scope"]["bytes_inspected"] = "measured at runtime; line-ending dependent"
    report.metadata["scan_configuration"]["fixture_sha256"] = fixture_hash()
    return render_consultant_markdown(report, assessment_date="2026-09-17") + "\n\nFixture SHA-256: `" + fixture_hash() + "`\n"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--write", action="store_true", help="Deliberately replace candidate; invalidates prior signoff")
    args = p.parse_args()
    rendered = render()
    if args.write:
        from vibe_explainer.output import atomic_write_text
        atomic_write_text(GOLDEN, rendered, overwrite=True)
        print(f"Wrote candidate {GOLDEN}; analyst approval still required")
        return 0
    same = GOLDEN.exists() and GOLDEN.read_text(encoding="utf-8") == rendered
    print("Golden comparison: " + ("PASS" if same else "FAIL; review the diff before --write"))
    return 0 if same else 1


if __name__ == "__main__":
    raise SystemExit(main())
