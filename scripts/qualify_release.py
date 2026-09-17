"""Run every locally verifiable Vibe Explainer release gate without network access."""

from __future__ import annotations

import json
import argparse
import hashlib
import os
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.2.0a1"
REPORT_SCHEMA = "2.0"
VALIDATION_SCHEMA = "2.0"


class Qualification:
    def __init__(self) -> None:
        self.results: list[tuple[str, bool, str]] = []

    def record(self, name: str, passed: bool, detail: str = "") -> None:
        self.results.append((name, passed, detail))
        print(f"[{'PASS' if passed else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))

    def command(self, name: str, command: list[str], *, cwd: Path = ROOT, expect: int = 0) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
        except OSError as exc:
            self.record(name, False, f"missing tooling or execution failure: {exc}")
            return subprocess.CompletedProcess(command, 127, "", str(exc))
        passed = result.returncode == expect
        detail = "ok" if passed else f"exit {result.returncode}; {result.stderr.strip()[-500:]}"
        self.record(name, passed, detail)
        if name in {"pytest", "branch coverage run", "branch coverage >= 90%"}:
            print(result.stdout.strip()[-1500:], flush=True)
        return result

    def finish(self) -> int:
        failures = [name for name, passed, _detail in self.results if not passed]
        print(f"\nQualification: {len(self.results) - len(failures)}/{len(self.results)} gates passed.")
        if failures:
            print("Blocking gates: " + ", ".join(failures))
            return 1
        return 0


def _artifact_names(wheel: Path, sdist: Path) -> tuple[list[str], str]:
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
        metadata = archive.read(metadata_name).decode("utf-8")
    with tarfile.open(sdist, "r:gz") as archive:
        names.extend(archive.getnames())
    return names, metadata


def _contents_safe(names: list[str]) -> tuple[bool, str]:
    banned_parts = {".git", ".env", ".venv", "venv", "htmlcov", "__pycache__"}
    for name in names:
        normalized = name.lower().replace("\\", "/")
        if banned_parts.intersection(normalized.split("/")) or normalized.endswith("/.coverage"):
            return False, f"forbidden package path: {name}"
        if "aletheia-core-assessment" in normalized:
            return False, f"stale customer-looking assessment: {name}"
    return True, f"{len(names)} archived paths inspected"


def _has_default_award_fields(value: object) -> bool:
    forbidden = {"score", "severity", "highest_risk_severity", "readiness_level", "readiness_name"}
    if isinstance(value, dict):
        return bool(forbidden.intersection(value)) or any(_has_default_award_fields(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_default_award_fields(item) for item in value)
    return False


def _python_in(venv_root: Path) -> Path:
    return venv_root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _cli_in(venv_root: Path) -> Path:
    return venv_root / ("Scripts/vibe-explainer.exe" if os.name == "nt" else "bin/vibe-explainer")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--large-targets", type=Path)
    parser.add_argument("--large-output", type=Path, default=Path(tempfile.gettempdir()) / "vibe-large-qualification")
    args = parser.parse_args()
    q = Qualification()
    commit = q.command("source identity", ["git", "rev-parse", "HEAD"])
    runtime_version = q.command(
        "runtime version", [sys.executable, "-c", "import vibe_explainer; print(vibe_explainer.__version__)"],
    )
    q.record(
        "source version is release candidate",
        runtime_version.returncode == 0 and runtime_version.stdout.strip() == VERSION,
        f"commit {commit.stdout.strip() or 'unavailable'}; version {runtime_version.stdout.strip() or 'unavailable'}",
    )
    q.command("product-boundary check", [sys.executable, "scripts/check_product_boundary.py"])
    q.command("pytest", [sys.executable, "-m", "pytest", "-q"])
    q.command("branch coverage run", [sys.executable, "-m", "coverage", "run", "-m", "pytest", "-q"])
    q.command("branch coverage >= 90%", [sys.executable, "-m", "coverage", "report", "--fail-under=90"])
    q.command("frozen detection review", [sys.executable, "scripts/review_detection.py"])
    q.command("golden report regression", [sys.executable, "scripts/golden_report.py"])
    signoff = (ROOT / "docs" / "GOLDEN-REPORT-SIGNOFF.md").read_text(encoding="utf-8")
    fields = dict(line.split(": ", 1) for line in signoff.splitlines() if ": " in line and not line.startswith("-"))
    golden_hash = hashlib.sha256((ROOT / "examples/sample-assessment/beta-golden.md").read_text(encoding="utf-8").replace("\r\n", "\n").encode()).hexdigest()
    q.record("golden analyst signoff", fields.get("Status") == "APPROVED"
             and fields.get("Reviewer", "pending") != "pending"
             and fields.get("Approved output SHA-256") == golden_hash
             and fields.get("Review date", "pending") != "pending"
             and "- [ ]" not in signoff, "requires named analyst review of pinned artifact")
    if args.large_targets:
        q.command("large repository qualification", [sys.executable, "scripts/qualify_large_repos.py", "--targets", str(args.large_targets.resolve()), "--output", str(args.large_output.resolve())])
    else:
        q.record("large repository qualification", False, "external inputs missing: pass --large-targets; no network fetch is performed")

    with tempfile.TemporaryDirectory(prefix="vibe-explainer-qualification-") as temp:
        temp_root = Path(temp)
        metrics = temp_root / "metrics.json"
        metric_result = q.command(
            "validation metric gate",
            [sys.executable, "-m", "vibe_explainer.validation", "--output", str(metrics), "--metrics-gate"],
        )
        exact_result = q.command(
            "validation exact-label gate",
            [sys.executable, "-m", "vibe_explainer.validation", "--output", str(metrics), "--check"],
        )
        metrics_payload = json.loads(metrics.read_text(encoding="utf-8")) if metrics.exists() else {}
        checked_metrics = json.loads((ROOT / "validation" / "metrics.json").read_text(encoding="utf-8"))
        q.record("validation artifact reproducible", metrics_payload == checked_metrics, metrics_payload.get("corpus_version", "missing"))
        known = metrics_payload.get("known_mismatches", [])
        q.record("known benchmark misses published", "py_obfuscated_import" in known, ", ".join(known) or "none")
        review = metrics_payload.get("label_review", {})
        q.record(
            "independent corpus-label review",
            review.get("status") == "INDEPENDENTLY_REVIEWED" and review.get("reviewed_version") == metrics_payload.get("corpus_version"),
            review.get("status", "missing"),
        )

        artifact_dir = temp_root / "artifacts"
        artifact_dir.mkdir()
        build_result = q.command(
            "build sdist and wheel",
            [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(artifact_dir)],
        )
        wheels = list(artifact_dir.glob("*.whl"))
        sdists = list(artifact_dir.glob("*.tar.gz"))
        if build_result.returncode == 0 and len(wheels) == len(sdists) == 1:
            names, metadata = _artifact_names(wheels[0], sdists[0])
            q.record("package metadata", f"Version: {VERSION}" in metadata and "License-Expression: Apache-2.0" in metadata, "version/license")
            safe, detail = _contents_safe(names)
            q.record("package contents", safe, detail)
        else:
            q.record("package metadata", False, "artifacts unavailable")
            q.record("package contents", False, "artifacts unavailable")

        environment = temp_root / "venv"
        try:
            venv.EnvBuilder(with_pip=True, clear=True).create(environment)
            q.record("isolated environment", True)
        except Exception as exc:  # noqa: BLE001
            q.record("isolated environment", False, str(exc))
        vpython = _python_in(environment)
        cli = _cli_in(environment)
        if wheels and vpython.exists():
            q.command("clean wheel install", [str(vpython), "-m", "pip", "install", "--no-deps", "--no-index", str(wheels[0])])
            version_result = q.command("installed CLI version", [str(cli), "--version"], cwd=temp_root)
            q.command("installed CLI help", [str(cli), "--help"], cwd=temp_root)
            q.command("installed import isolated from source", [str(vpython), "-I", "-c", "import pathlib,sys,vibe_explainer; assert pathlib.Path(vibe_explainer.__file__).is_relative_to(sys.prefix)"], cwd=temp_root)
            q.record("installed version identity", version_result.stdout.strip() == f"vibe-explainer {VERSION}", version_result.stdout.strip())

            fixture = ROOT / "examples" / "analyst-review-fixture"
            terminal = q.command("terminal assessment smoke", [str(cli), str(fixture)], cwd=temp_root)
            json_path = temp_root / "review.json"
            markdown_path = temp_root / "review.md"
            q.command("JSON assessment smoke", [str(cli), str(fixture), "--json", "--out", str(json_path)], cwd=temp_root)
            q.command("Markdown assessment smoke", [str(cli), str(fixture), "--report", "--out", str(markdown_path)], cwd=temp_root)
            q.command("output non-overwrite", [str(cli), str(fixture), "--json", "--out", str(json_path)], expect=2)
            payload = json.loads(json_path.read_text(encoding="utf-8")) if json_path.exists() else {}
            executive = payload.get("executive_summary", {})
            no_awards = (
                not payload.get("metadata", {}).get("experimental_scoring_enabled", True)
                and not _has_default_award_fields(payload)
            )
            q.record("default output excludes experimental scoring", no_awards)
            manifest = payload.get("assessment_manifest", {})
            provenance_ok = all(key in manifest for key in (
                "engine", "engine_version", "schema_version", "repository_revision",
                "assessment_completeness", "scan_configuration", "asi_catalog",
            ))
            q.record("report provenance manifest", provenance_ok)
            q.record(
                "schema versions",
                manifest.get("schema_version") == REPORT_SCHEMA and metrics_payload.get("schema_version") == VALIDATION_SCHEMA,
            )

            planted = "sk-THIS_IS_A_PLANTED_RELEASE_QUALIFICATION_SECRET"
            secret_repo = temp_root / "secret-fixture"
            secret_repo.mkdir()
            (secret_repo / "app.py").write_text(
                f'from openai import OpenAI\nOPENAI_API_KEY = "{planted}"\n', encoding="utf-8"
            )
            secret_out = temp_root / "secret-review.json"
            q.command("credential-redaction smoke", [str(cli), str(secret_repo), "--json", "--out", str(secret_out)])
            generated = "\n".join(
                path.read_text(encoding="utf-8", errors="replace")
                for path in (json_path, markdown_path, secret_out) if path.exists()
            )
            q.record("generated artifacts contain no planted credentials", planted not in generated)
        else:
            for name in (
                "clean wheel install", "installed CLI version", "installed version identity",
                "terminal assessment smoke", "JSON assessment smoke", "Markdown assessment smoke",
                "output non-overwrite", "default output excludes experimental scoring",
                "report provenance manifest", "schema versions", "credential-redaction smoke",
                "generated artifacts contain no planted credentials",
            ):
                q.record(name, False, "wheel or isolated Python unavailable")

    stale = list((ROOT / "examples").rglob("*aletheia*assessment*"))
    q.record("stale customer-looking assessments absent", not stale, ", ".join(map(str, stale)) or "none")
    return q.finish()


if __name__ == "__main__":
    raise SystemExit(main())
