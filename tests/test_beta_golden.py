import importlib.util
from pathlib import Path


def test_complete_golden_candidate_is_stable():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("golden_report", root / "scripts" / "golden_report.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.render() == module.GOLDEN.read_text(encoding="utf-8")
