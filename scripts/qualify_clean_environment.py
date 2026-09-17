"""Qualify a committed revision in a separate checkout and fresh virtualenv.

Only developer tooling installation uses the network. Target repositories remain
inert, external data. Results and build logs survive temporary-directory cleanup.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--revision", default="HEAD")
    p.add_argument("--large-targets", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    revision = subprocess.check_output(["git", "rev-parse", args.revision], cwd=ROOT, text=True).strip()
    results = {"source_sha": revision, "python": sys.version, "steps": []}

    def run(name, command, cwd, classification):
        print(f"Running {name}", flush=True)
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
        (output / f"{name}.log").write_text(result.stdout + "\n" + result.stderr, encoding="utf-8")
        results["steps"].append({"name": name, "exit_code": result.returncode,
                                 "failure_class": classification if result.returncode else None})
        print(f"{name}: exit {result.returncode}", flush=True)
        return result.returncode

    with tempfile.TemporaryDirectory(prefix="vibe-clean-") as temp:
        temp = Path(temp)
        source = temp / "source"
        code = run("checkout", ["git", "clone", "--no-hardlinks", "--no-checkout", str(ROOT), str(source)], temp, "source checkout failure")
        if not code:
            code = run("revision", ["git", "checkout", "--detach", revision], source, "source checkout failure")
        environment = temp / "environment"
        if not code:
            code = run("venv", [sys.executable, "-m", "venv", str(environment)], temp, "missing developer tooling")
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if not code:
            code = run("tooling", [str(python), "-m", "pip", "install", "-r", str(source / "requirements-qualification.txt")], temp, "developer tooling acquisition failure")
        if not code:
            code = run("qualification", [str(python), "-u", "scripts/qualify_release.py", "--large-targets", str(args.large_targets.resolve()), "--large-output", str(output / "large-repos")], source, "release blocker; inspect per-gate log for packaging/test/validation failures")
    (output / "result.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
