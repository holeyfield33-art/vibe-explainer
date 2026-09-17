import json
from pathlib import Path
from unittest.mock import patch

import pytest

from vibe_explainer.cli import main, _git_provenance
from vibe_explainer.output import atomic_write_text
from vibe_explainer.scan_budget import ACTIVE, ScanBudget


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "target"
    root.mkdir()
    for name in ("a.py", "b.py", "c.py"):
        (root / name).write_text("from openai import OpenAI\nclient = OpenAI()\n", encoding="utf-8")
    return root


@pytest.mark.parametrize("args,reason", [
    (["--max-files", "1"], "file count budget"),
    (["--max-bytes", "60"], "total byte budget"),
    (["--max-seconds", "0.000001"], "time budget"),
])
@pytest.mark.parametrize("format", ["--json", "--report"])
def test_partial_artifact(repository, tmp_path, args, reason, format):
    out = tmp_path / "report"
    assert main([str(repository), format, "--out", str(out), *args]) == 0
    text = out.read_text(encoding="utf-8")
    assert "PARTIAL" in text and reason in text
    assert "Absence of evidence outside inspected scope is not evidence of absence" in text
    if format == "--json":
        report = json.loads(text)
        scope = report["metadata"]["scan_scope"]
        assert scope["files_inspected"] <= 1
        assert report["assessment_manifest"]["scan_scope"] == scope
        if reason != "time budget":
            assert report["executive_summary"]["total_findings"] > 0
    else:
        assert text.startswith("# AI Repository Evidence Review")
    assert not list(tmp_path.glob(".report.*.tmp"))
    assert ACTIVE.get() is None


def test_clock_budget_is_deterministic_and_retains_evidence(repository, tmp_path):
    # Advance time only after discovery has gathered its first file's evidence.
    from vibe_explainer import cli
    from vibe_explainer.attack_surface import build_attack_surface
    now = [0.0]

    def advance(discovery):
        assert discovery.findings
        now[0] = 2.0
        return build_attack_surface(discovery)

    out = tmp_path / "report.json"
    with patch("vibe_explainer.scan_budget.time.monotonic", side_effect=lambda: now[0]), patch(
        "vibe_explainer.attack_surface.build_attack_surface", side_effect=advance
    ):
        assert cli.main([str(repository), "--json", "--max-seconds", "1", "--out", str(out)]) == 0
    payload = json.loads(out.read_text())
    assert payload["executive_summary"]["total_findings"] > 0
    assert payload["metadata"]["assessment_completeness"] == "PARTIAL"
    assert payload["metadata"]["scan_scope"]["budget_exhausted_reason"] == "time budget (1.0s) reached"
    assert not payload["controls"]["by_status"]["NOT_FOUND"]
    assert not payload["controls"]["by_status"]["NOT_APPLICABLE"]


def test_failed_atomic_publish_preserves_previous_partial(repository, tmp_path):
    out = tmp_path / "report.json"
    assert main([str(repository), "--json", "--max-files", "1", "--out", str(out)]) == 0
    original = out.read_bytes()
    with patch("vibe_explainer.output.os.replace", side_effect=OSError("simulated publication failure")):
        with pytest.raises(OSError):
            atomic_write_text(out, '{"replacement":true}', overwrite=True)
    assert out.read_bytes() == original
    assert json.loads(original)["metadata"]["assessment_completeness"] == "PARTIAL"
    assert not list(tmp_path.glob(".report.json.*.tmp"))
    assert main([str(repository), "--json", "--max-files", "1", "--out", str(out)]) == 2


@pytest.mark.parametrize("flag,value", [("--max-files", "0"), ("--max-bytes", "-1"), ("--max-seconds", "nan"), ("--max-seconds", "inf")])
def test_invalid_budgets(flag, value):
    with pytest.raises(SystemExit) as exc:
        main([flag, value])
    assert exc.value.code == 2


def test_budget_rejects_outside_link(repository, tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text("raise RuntimeError('must never execute')")
    link = repository / "escape.py"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("host cannot create symlinks")
    budget = ScanBudget(repository)
    assert not budget.admit(link, 1)
    assert budget.skipped["escape.py"] == "symlink/outside root"


def test_provenance_disables_target_fsmonitor(repository):
    import subprocess
    with patch("vibe_explainer.cli.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
        _git_provenance(repository)
    assert len(run.call_args_list) == 3
    for call in run.call_args_list:
        assert "core.fsmonitor=false" in call.args[0]


def test_parse_failure_is_reported_and_target_not_executed(repository, tmp_path):
    (repository / "broken.py").write_text("from openai import (\n")
    marker = tmp_path / "EXECUTED"
    (repository / "setup.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
    out = tmp_path / "report.json"
    assert main([str(repository), "--json", "--out", str(out)]) == 0
    payload = json.loads(out.read_text())
    assert "broken.py" in payload["metadata"]["scan_scope"]["parse_failures"]
    assert payload["metadata"]["assessment_completeness"] == "PARTIAL"
    assert not marker.exists()
