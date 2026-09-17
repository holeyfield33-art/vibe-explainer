"""Qualify externally cloned targets as inert data; never install target packages.

The watchdog is a FAIL condition, never a successful budget termination.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
TARGETS = ("openai/openai-python", "langchain-ai/langgraph", "BerriAI/litellm")


def worker(arguments: list[str]) -> int:
    from vibe_explainer.cli import main
    target = Path(arguments[0]).resolve()

    def audit(event, args):
        if event == "exec":
            filename = getattr(args[0], "co_filename", "")
            if filename and not filename.startswith("<") and Path(filename).resolve().is_relative_to(target):
                raise RuntimeError("qualification refused target execution/import")
        if event == "subprocess.Popen":
            command = args[1]
            prefix = ["git", "--no-optional-locks", "-c", "core.fsmonitor=false"]
            allowed = command[:4] == prefix if isinstance(command, list) else command.startswith(subprocess.list2cmdline(prefix) + " ")
            if not allowed:
                raise RuntimeError("qualification refused non-provenance subprocess")

    sys.addaudithook(audit)
    return main(arguments)


def validate(payload: dict) -> None:
    manifest = payload["assessment_manifest"]
    assert manifest["repository_revision"]["commit"], "missing provenance"
    assert manifest["assessment_completeness"] in {"COMPLETE", "PARTIAL", "AGGREGATED"}
    scope = manifest["scan_scope"]
    assert scope["files_discovered"] >= scope["files_inspected"] >= 0
    assert scope["files_skipped"] == scope["files_discovered"] - scope["files_inspected"]
    assert scope["bytes_inspected"] >= 0
    if scope["budget_exhausted_reason"]:
        assert manifest["assessment_completeness"] == "PARTIAL"
    for rows in payload["ai_inventory"]["categories"].values():
        for row in rows:
            path = PurePosixPath(row["file"])
            assert not path.is_absolute() and ".." not in path.parts
    from vibe_explainer.security_utils import redact_structure
    assert redact_structure(payload) == payload, "non-redacted recognized secret pattern"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--targets", type=Path, required=True, help="Directory containing the three external clones")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--max-seconds", type=float, default=2.0)
    p.add_argument("--max-files", type=int, default=20_000)
    p.add_argument("--max-bytes", type=int, default=200_000_000)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    rows = []
    for name in TARGETS:
        target = (args.targets / name.split("/")[1]).resolve()
        row = {"repository": name, "errors": [], "artifacts": []}
        try:
            sha = subprocess.check_output(["git", "-C", str(target), "rev-parse", "HEAD"], text=True).strip()
            row["upstream_sha"] = sha
            for mode, suffix in (("--json", "json"), ("--report", "md")):
                output = (args.output / f"{target.name}.{suffix}").resolve()
                command = [sys.executable, "-I", str(Path(__file__).resolve()), "--worker", str(target), mode,
                           "--max-seconds", str(args.max_seconds), "--max-files", str(args.max_files),
                           "--max-bytes", str(args.max_bytes), "--out", str(output), "--force"]
                started = time.monotonic()
                run = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=args.max_seconds + 30)
                assert run.returncode == 0, f"CLI exit {run.returncode}: {run.stderr[-300:]}"
                artifact = output.read_text(encoding="utf-8")
                row["artifacts"].append(str(output))
                if suffix == "json":
                    payload = json.loads(artifact)
                    validate(payload)
                    assert payload["assessment_manifest"]["repository_revision"]["commit"] == sha
                    row.update(payload["metadata"]["scan_scope"])
                    row.update(payload["metadata"]["evidence_counts"])
                    row["completion_state"] = payload["metadata"]["assessment_completeness"]
                    row["process_seconds"] = round(time.monotonic() - started, 3)
                else:
                    assert artifact.startswith("# AI Repository Evidence Review")
                    assert "Assessment completeness" in artifact and "## Limitations" in artifact
            row["execution_guard"] = "target exec/import refused by Python audit hook; only hardened git provenance subprocess permitted"
        except (AssertionError, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
            row["errors"].append(str(exc))
        rows.append(row)
        print(f"{'FAIL' if row['errors'] else 'PASS'} {name}: {row.get('completion_state')}; {row.get('budget_exhausted_reason')}", flush=True)
    from vibe_explainer.output import atomic_write_text
    atomic_write_text(args.output / "qualification.json", json.dumps(rows, indent=2), overwrite=True)
    return int(any(row["errors"] for row in rows))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        raise SystemExit(worker(sys.argv[2:]))
    raise SystemExit(main())
