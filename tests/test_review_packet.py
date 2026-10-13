import json
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

from vibe_explainer.cli import main
from vibe_explainer.output import OutputExistsError, atomic_write_bytes
from vibe_explainer.review_packet import verify_review_packet

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "basic-chatbot"


class TestReviewPacket(unittest.TestCase):
    def _create(self, path: Path, fixture: Path = FIXTURE) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "vibe_explainer", str(fixture), "--review-packet", str(path)],
            cwd=ROOT, capture_output=True, text=True, timeout=40,
        )

    def test_packet_is_paired_unsigned_and_verifiable(self):
        with tempfile.TemporaryDirectory() as directory:
            packet = Path(directory) / "candidate.zip"
            result = self._create(packet)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = verify_review_packet(packet)
            self.assertEqual(manifest["status"], "PENDING_ANALYST_REVIEW")
            self.assertFalse(manifest["customer_delivery_approved"])
            with zipfile.ZipFile(packet) as archive:
                evidence = json.loads(archive.read("evidence.json"))
                markdown = archive.read("review.md").decode("utf-8")
                checklist = archive.read("analyst-checklist.md").decode("utf-8")
            self.assertEqual(manifest["assessment"], evidence["assessment_manifest"])
            self.assertNotIn("repository_path", evidence["metadata"])
            self.assertNotIn(str(ROOT), json.dumps(evidence))
            self.assertIn("UNREVIEWED CANDIDATE", markdown)
            self.assertIn("Reviewer name and organization: PENDING", checklist)
            self.assertNotIn("Experimental score:", markdown)

    def test_direct_cli_packet_and_atomic_overwrite_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            packet = Path(directory) / "candidate.zip"
            self.assertEqual(main([str(FIXTURE), "--review-packet", str(packet)]), 0)
            original = packet.read_bytes()
            self.assertEqual(main([str(FIXTURE), "--review-packet", str(packet)]), 2)
            self.assertEqual(packet.read_bytes(), original)
            with self.assertRaises(OutputExistsError):
                atomic_write_bytes(packet, b"replacement")
            self.assertEqual(packet.read_bytes(), original)
            self.assertEqual(main([str(FIXTURE), "--review-packet", str(packet), "--force"]), 0)
            verify_review_packet(packet)

    def test_packet_rejects_tampering_and_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            packet = Path(directory) / "candidate.zip"
            self.assertEqual(self._create(packet).returncode, 0)
            original = packet.read_bytes()
            self.assertEqual(self._create(packet).returncode, 2)
            self.assertEqual(packet.read_bytes(), original)
            with zipfile.ZipFile(packet) as archive:
                files = {name: archive.read(name) for name in archive.namelist()}
            files["review.md"] += b"\nUnreviewed edit\n"
            with zipfile.ZipFile(packet, "w") as archive:
                for name, content in files.items():
                    archive.writestr(name, content)
            with self.assertRaisesRegex(ValueError, "hash or byte count mismatch"):
                verify_review_packet(packet)

    def test_packet_rejects_scoring_and_single_output_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            packet = Path(directory) / "candidate.zip"
            for incompatible in ("--experimental-scoring", "--json", "--report"):
                result = subprocess.run(
                    [sys.executable, "-m", "vibe_explainer", str(FIXTURE),
                     "--review-packet", str(packet), incompatible],
                    cwd=ROOT, capture_output=True, text=True, timeout=20,
                )
                self.assertEqual(result.returncode, 2)
                self.assertFalse(packet.exists())

    def test_packet_rejects_duplicate_members(self):
        with tempfile.TemporaryDirectory() as directory:
            packet = Path(directory) / "candidate.zip"
            self.assertEqual(self._create(packet).returncode, 0)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(packet, "a") as archive:
                    archive.writestr("review.md", "replacement")
            with self.assertRaisesRegex(ValueError, "unexpected or duplicate"):
                verify_review_packet(packet)

    def test_packet_preserves_redaction_across_all_members(self):
        with tempfile.TemporaryDirectory() as directory:
            packet = Path(directory) / "candidate.zip"
            result = self._create(packet, ROOT / "tests" / "fixtures" / "hardcoded-credential")
            self.assertEqual(result.returncode, 0, result.stderr)
            with zipfile.ZipFile(packet) as archive:
                joined = b"\n".join(archive.read(name) for name in archive.namelist())
            self.assertNotIn(b"sk-proj-", joined)
            self.assertNotIn(b"abcdefghijklmnopqrstuvwxyz012345", joined)
