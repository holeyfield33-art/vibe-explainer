import importlib.util
from pathlib import Path


def test_complete_golden_candidate_is_stable():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("golden_report", root / "scripts" / "golden_report.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.render() == module.GOLDEN.read_text(encoding="utf-8")


def test_golden_is_stable_across_checkout_line_endings(tmp_path):
    import shutil
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("golden_crlf", root / "scripts" / "golden_report.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    copied = tmp_path / "analyst-review-fixture"
    shutil.copytree(module.FIXTURE, copied)
    for file in copied.rglob("*"):
        if file.is_file():
            file.write_bytes(file.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\n", "\r\n").encode())
    module.FIXTURE = copied
    assert module.render() == module.GOLDEN.read_text(encoding="utf-8")
