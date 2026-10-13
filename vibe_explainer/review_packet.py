"""Build and verify an unsigned analyst review packet for one scan."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path

from .security_report import VibeExplainerReport

_FILES = frozenset({"evidence.json", "review.md", "manifest.json", "analyst-checklist.md"})
_MAX_ENTRY_BYTES = 50_000_000


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_review_packet(report: VibeExplainerReport, *, evidence_json: str, review_markdown: str) -> bytes:
    """Bundle paired outputs and provenance without asserting analyst approval."""
    if report.metadata.get("experimental_scoring_enabled"):
        raise ValueError("review packets cannot contain experimental scoring")
    evidence = json.loads(evidence_json)
    if evidence.get("assessment_manifest") != report.to_dict().get("assessment_manifest"):
        raise ValueError("evidence JSON does not match the report's assessment manifest")
    banner = "> **UNREVIEWED CANDIDATE — not approved for customer delivery.**\n\n"
    review_markdown = banner + review_markdown
    evidence_bytes = evidence_json.encode("utf-8")
    review_bytes = review_markdown.encode("utf-8")
    checks = (
        "# Analyst review record — pending\n\n"
        "This template is not a signoff. Review the exact packet and record approval "
        "outside the generated archive only after checking every item.\n\n"
        "- Reviewer name and organization: PENDING\n"
        "- Review date: PENDING\n"
        "- Evidence SHA-256: `" + _sha256(evidence_bytes) + "`\n"
        "- Markdown SHA-256: `" + _sha256(review_bytes) + "`\n\n"
        "- [ ] Repository identity, commit, branch, dirty state and scope verified\n"
        "- [ ] Exclusions, skipped files, partial status and context labels reviewed\n"
        "- [ ] Findings, relationships, controls and concern statements checked against source\n"
        "- [ ] ASI mapping and catalog status checked, if supplied\n"
        "- [ ] Sensitive excerpts and limitations reviewed for customer distribution\n"
        "- [ ] Independent detection-quality and release gates confirmed separately\n"
        "- [ ] Customer-specific conclusions and wording approved by a named analyst\n"
    ).encode("utf-8")
    manifest = {
        "contract_version": 1,
        "status": "PENDING_ANALYST_REVIEW",
        "customer_delivery_approved": False,
        "assessment": evidence["assessment_manifest"],
        "files": {
            "evidence.json": {"sha256": _sha256(evidence_bytes), "bytes": len(evidence_bytes)},
            "review.md": {"sha256": _sha256(review_bytes), "bytes": len(review_bytes)},
            "analyst-checklist.md": {"sha256": _sha256(checks), "bytes": len(checks)},
        },
    }
    entries = {
        "evidence.json": evidence_bytes,
        "review.md": review_bytes,
        "analyst-checklist.md": checks,
        "manifest.json": (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
    }
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(entries):
            archive.writestr(name, entries[name])
    return stream.getvalue()


def verify_review_packet(path: str | Path) -> dict:
    """Check packet members, hashes and the recorded assessment identity."""
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) != len(_FILES) or {i.filename for i in infos} != _FILES:
            raise ValueError("unexpected or duplicate packet members")
        if any(i.file_size > _MAX_ENTRY_BYTES for i in infos):
            raise ValueError("packet member exceeds verification limit")
        members = {i.filename: archive.read(i) for i in infos}
    manifest = json.loads(members["manifest.json"])
    if not isinstance(manifest, dict):
        raise ValueError("packet manifest must be an object")
    if manifest.get("contract_version") != 1 or manifest.get("status") != "PENDING_ANALYST_REVIEW" or manifest.get("customer_delivery_approved") is not False:
        raise ValueError("packet review status is invalid")
    if not isinstance(manifest.get("files"), dict) or set(manifest["files"]) != _FILES - {"manifest.json"}:
        raise ValueError("packet file inventory is invalid")
    for name, expected in manifest["files"].items():
        if expected != {"sha256": _sha256(members[name]), "bytes": len(members[name])}:
            raise ValueError(f"packet hash or byte count mismatch: {name}")
    evidence = json.loads(members["evidence.json"])
    if not isinstance(evidence, dict):
        raise ValueError("packet evidence must be an object")
    if evidence.get("assessment_manifest") != manifest.get("assessment"):
        raise ValueError("packet assessment identity mismatch")
    if evidence.get("metadata", {}).get("experimental_scoring_enabled"):
        raise ValueError("experimental scoring is not eligible for a review packet")
    if not members["review.md"].startswith(b"> **UNREVIEWED CANDIDATE"):
        raise ValueError("candidate warning is missing")
    return manifest
