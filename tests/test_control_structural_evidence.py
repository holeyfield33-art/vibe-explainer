import tempfile
import unittest
from pathlib import Path

from vibe_explainer.ai_discovery import AIFinding
from vibe_explainer.controls import (
    EFFECTIVENESS_UNVERIFIED,
    ENFORCEMENT_NOT_ESTABLISHED,
    _EvidenceMatch,
    _python_structures,
    _structural_coverage,
)


class TestAdversarialEvidenceForAllControls(unittest.TestCase):
    """Issue #7: cheap tokens must not be reported as enforced controls."""

    def _coverage(self, control_id: str, source: str, match_line: int, sink_line: int, tag: str):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(source, encoding="utf-8")
            match = _EvidenceMatch("app.py", match_line, tag, "high", tag)
            finding = AIFinding("tool_agent", "Protected operation", "app.py", sink_line, "sink", "high")
            return _structural_coverage(root, _python_structures(root), control_id, [match], [finding])

    def test_c01_inventory_header_is_artifact_not_enforcement(self):
        from tests.test_controls import _assess, _control
        control = _control(_assess("controls-docs"), "C01")
        self.assertEqual(control.enforcement_status, ENFORCEMENT_NOT_ESTABLISHED)
        self.assertEqual(control.effectiveness_status, EFFECTIVENESS_UNVERIFIED)

    def test_c02_threat_model_header_is_artifact_not_enforcement(self):
        from tests.test_controls import _assess, _control
        control = _control(_assess("controls-docs"), "C02")
        self.assertEqual(control.enforcement_status, ENFORCEMENT_NOT_ESTABLISHED)
        self.assertEqual(control.effectiveness_status, EFFECTIVENESS_UNVERIFIED)

    def test_c03_to_c06_and_c09_to_c12_reject_token_gaming(self):
        cases = {
            "C03": ("def run(x):\n    validate_input(x)\n    dangerous(x)\n", 2, 3, "Explicit input sanitizer/validator"),
            "C04": ("def run(x):\n    dangerous(x)\n    validate_output(x)\n", 3, 2, "Explicit output sanitizer/validator"),
            "C05": ("def run(x):\n    check_permission(x, 'run')\n    dangerous(x)\n", 2, 3, "Explicit permission/authorization check"),
            "C06": ("def run(x):\n    require_approval(x)\n    dangerous(x)\n", 2, 3, "Explicit approval gate"),
            "C09": ("def run(x):\n    verify_source(x)\n    dangerous(x)\n", 2, 3, "Source/content filter function"),
            "C10": ("def run(x):\n    allowed_tools = {'safe'}\n    dangerous(x)\n", 2, 3, "Default-deny / explicit tool allowlist"),
            "C11": ("def run(x):\n    check_access(x)\n    dangerous(x)\n", 2, 3, "Explicit access-control function"),
            "C12": ("def run(x):\n    dangerous(x)\n    check_permission(x, 'run')\n", 3, 2, "Auth/permission check before action"),
        }
        for control_id, args in cases.items():
            with self.subTest(control_id=control_id):
                covered, uncovered = self._coverage(control_id, *args)
                self.assertEqual(covered, set())
                self.assertEqual(len(uncovered), 1)

    def test_c07_dead_code_logging_does_not_cover_live_surface(self):
        source = "def dead():\n    audit_log('x')\n\ndef live(x):\n    dangerous(x)\n"
        covered, uncovered = self._coverage("C07", source, 2, 5, "Audit-specific log call")
        self.assertEqual(covered, set())
        self.assertEqual(len(uncovered), 1)

    def test_c08_environment_access_is_artifact_only(self):
        from tests.test_controls import _assess, _control
        control = _control(_assess("basic-chatbot"), "C08")
        self.assertEqual(control.enforcement_status, ENFORCEMENT_NOT_ESTABLISHED)
        self.assertEqual(control.effectiveness_status, EFFECTIVENESS_UNVERIFIED)


if __name__ == "__main__":
    unittest.main()
