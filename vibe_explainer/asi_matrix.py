"""Map a Vibe Explainer security report onto the Agent Security Index (ASI).

This module is intentionally a bridge, not a second scanner and not an attack detector.
It consumes two already-produced artifacts:

1. a ``VibeExplainerReport`` containing repository evidence; and
2. a local ASI machine-readable export (combined JSON, attack-class JSON, or export dir).

The output answers: "which ASI rows are relevant to the observed repository surface,
what Vibe evidence is related to those rows, and what repository evidence exists for
mitigations Vibe knows how to recognize?"

It does *not* claim exploitability, attack presence, mitigation effectiveness, or ASI
validation. Missing evidence remains missing evidence.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "1.0"

# Narrow, auditable bridges from Vibe's existing control evidence to mitigation IDs
# used by Agent Security Index. A mapping means "this Vibe control can provide some
# repository evidence relevant to this mitigation" -- never that the mitigation is
# validated or fully implemented.
_CONTROL_TO_ASI_MITIGATIONS: dict[str, tuple[str, ...]] = {
    "C03": ("untrusted-io", "schema-gov"),
    "C04": ("output-dlp", "schema-gov"),
    "C05": ("least-privilege", "capability-attest"),
    "C06": ("hitl",),
    "C07": ("telemetry", "trajectory"),
    "C08": ("output-dlp",),
    "C09": ("rag-validate", "provenance"),
    "C10": ("allowlist-servers", "least-privilege", "schema-gov"),
    "C11": ("least-privilege", "isolation"),
    "C12": ("tool-sandbox", "hitl", "least-privilege"),
}

# Only direct evidence bridges are listed. Vibe may consider many more ASI rows
# relevant by protocol, but it must not manufacture an attack-specific mapping.
_RISK_CATEGORY_TO_AAC: dict[str, tuple[str, ...]] = {
    "INPUT_SECURITY": ("AAC-01",),
    "RAG_SECURITY": ("AAC-02",),
    "SECRET_EXPOSURE": ("AAC-09",),
    "HIGH_IMPACT_ACTION": ("AAC-11", "AAC-16"),
}

_STATUS_RANK = {
    "DETECTED": 4,
    "PARTIAL": 3,
    "NOT_DETECTED": 2,
    "UNKNOWN": 1,
    "NOT_APPLICABLE": 0,
    "UNASSESSED": -1,
}


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"ASI catalog path does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"ASI catalog is not valid JSON: {path}: {exc}") from exc


def _extract_attack_classes(payload: Any) -> list[dict[str, Any]]:
    """Accept current ASI export shapes without coupling to its frontend source."""
    if isinstance(payload, list):
        rows = [row for row in payload if isinstance(row, dict) and str(row.get("id", "")).startswith("AAC-")]
        return rows

    if not isinstance(payload, dict):
        return []

    for key in ("attackClasses", "attack_classes", "classes"):
        rows = payload.get(key)
        if isinstance(rows, list):
            extracted = _extract_attack_classes(rows)
            if extracted:
                return extracted

    for key in ("catalog", "data", "matrix"):
        nested = payload.get(key)
        extracted = _extract_attack_classes(nested)
        if extracted:
            return extracted

    return []


def load_asi_catalog(path: str | Path) -> dict[str, Any]:
    """Load an ASI export from a directory or JSON file.

    Directory mode prefers ``asi-catalog.json`` when it exists; otherwise it joins
    ``attack-classes*.json`` fragments in lexical order. This preserves Vibe's
    offline/deterministic design: no network fetch occurs here.
    """
    source = Path(path)
    metadata: dict[str, Any] = {}

    if source.is_dir():
        meta_path = source / "catalog-meta.json"
        if meta_path.is_file():
            meta_payload = _load_json(meta_path)
            if isinstance(meta_payload, dict):
                metadata = meta_payload

        combined = source / "asi-catalog.json"
        if combined.is_file():
            payload = _load_json(combined)
            classes = _extract_attack_classes(payload)
            if not metadata and isinstance(payload, dict):
                for key in ("meta", "metadata"):
                    if isinstance(payload.get(key), dict):
                        metadata = payload[key]
                        break
        else:
            classes = []
            fragments = sorted(source.glob("attack-classes*.json"))
            for fragment in fragments:
                classes.extend(_extract_attack_classes(_load_json(fragment)))
    else:
        payload = _load_json(source)
        classes = _extract_attack_classes(payload)
        if isinstance(payload, dict):
            for key in ("meta", "metadata"):
                if isinstance(payload.get(key), dict):
                    metadata = payload[key]
                    break

    if not classes:
        raise ValueError(
            "No AAC attack classes found. Provide an ASI export directory, "
            "asi-catalog.json, or attack-classes JSON file."
        )

    ids = [str(row.get("id", "")) for row in classes]
    duplicates = sorted({item for item in ids if ids.count(item) > 1})
    if duplicates:
        raise ValueError(f"Duplicate ASI attack-class IDs: {', '.join(duplicates)}")

    classes.sort(key=lambda row: str(row.get("id", "")))
    return {
        "metadata": metadata,
        "classes": classes,
        "source": str(source),
    }


def _detected_protocols(report: Any) -> list[str]:
    protocols: set[str] = set()
    categories = report.ai_inventory.get("categories", {})

    if categories.get("ai_usage") or categories.get("tool_agent"):
        protocols.add("Native")
    if categories.get("mcp"):
        protocols.add("MCP")
    if categories.get("rag_retrieval"):
        protocols.add("RAG")

    # These protocol forms are less consistently represented as dedicated discovery
    # categories today, so use already-redacted inventory text as a conservative hint.
    searchable: list[str] = []
    for items in categories.values():
        for item in items:
            searchable.extend((str(item.get("name", "")), str(item.get("evidence", ""))))
    joined = "\n".join(searchable).lower()
    if "a2a" in joined or "agent card" in joined:
        protocols.add("A2A")
    if "agent network protocol" in joined or " anp " in f" {joined} ":
        protocols.add("ANP")
    if "skill" in joined:
        protocols.add("Skills")

    return sorted(protocols)


def _control_statuses(report: Any) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for status, controls in report.controls.get("by_status", {}).items():
        for control in controls:
            cid = str(control.get("control_id", ""))
            if cid:
                result[cid] = {
                    "status": status,
                    "name": control.get("name"),
                    "confidence": control.get("confidence"),
                    "evidence": control.get("evidence", []),
                }
    return result


def _mitigation_to_controls() -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for control_id, mitigation_ids in _CONTROL_TO_ASI_MITIGATIONS.items():
        for mitigation_id in mitigation_ids:
            result.setdefault(mitigation_id, []).append(control_id)
    return result


def _best_control_status(control_ids: list[str], controls: dict[str, dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    evidence: list[dict[str, Any]] = []
    best = "UNASSESSED"
    best_rank = _STATUS_RANK[best]
    for control_id in control_ids:
        control = controls.get(control_id)
        if not control:
            continue
        status = str(control.get("status", "UNKNOWN"))
        rank = _STATUS_RANK.get(status, 0)
        if rank > best_rank:
            best, best_rank = status, rank
        evidence.append(
            {
                "control_id": control_id,
                "control_name": control.get("name"),
                "status": status,
                "confidence": control.get("confidence"),
            }
        )
    return best, evidence


def _risk_rows_for_class(report: Any, class_id: str, relevant: bool) -> list[dict[str, Any]]:
    mapped: list[dict[str, Any]] = []
    for scenario in report.risks.get("scenarios", []):
        category = str(scenario.get("category", ""))
        if class_id not in _RISK_CATEGORY_TO_AAC.get(category, ()):
            continue
        # AAC-16 is specifically MCP STDIO. A generic high-impact-action path should
        # only bridge there when an MCP surface was actually observed.
        if class_id == "AAC-16" and not relevant:
            continue
        mapped.append(
            {
                "risk_id": scenario.get("risk_id"),
                "category": category,
                "severity": scenario.get("severity"),
                "score": scenario.get("score"),
                "confidence": scenario.get("confidence"),
                "related_finding_ids": list(scenario.get("related_finding_ids", [])),
                "related_dataflow_ids": list(scenario.get("related_dataflow_ids", [])),
            }
        )
    return mapped


def map_report_to_asi(report: Any, catalog: dict[str, Any]) -> dict[str, Any]:
    """Map a completed Vibe security report to every published ASI attack class."""
    protocols = _detected_protocols(report)
    protocol_set = set(protocols)
    controls = _control_statuses(report)
    mitigation_controls = _mitigation_to_controls()
    ai_surface_detected = report.executive_summary.get("ai_surface") == "DETECTED"

    rows: list[dict[str, Any]] = []
    counts = {
        "EVIDENCE_CHAIN": 0,
        "CONTROL_GAP": 0,
        "CONTROL_EVIDENCE": 0,
        "RELEVANT_UNASSESSED": 0,
        "NOT_OBSERVED": 0,
    }

    for attack_class in catalog["classes"]:
        class_id = str(attack_class.get("id", ""))
        class_protocols = [str(p) for p in attack_class.get("protocols", [])]
        matched_protocols = sorted(protocol_set.intersection(class_protocols))
        relevant = bool(matched_protocols)
        if not relevant and ai_surface_detected and "Native" in class_protocols:
            relevant = True
            matched_protocols = ["Native"]

        mapped_risks = _risk_rows_for_class(report, class_id, relevant)
        proposed = [str(mid) for mid in attack_class.get("proposedMitigationIds", [])]
        mitigation_evidence: list[dict[str, Any]] = []
        for mitigation_id in proposed:
            mapped_controls = mitigation_controls.get(mitigation_id, [])
            status, control_evidence = _best_control_status(mapped_controls, controls)
            mitigation_evidence.append(
                {
                    "mitigation_id": mitigation_id,
                    "evidence_status": status,
                    "mapped_controls": control_evidence,
                    "note": "Repository evidence only; this does not validate ASI mitigation effectiveness.",
                }
            )

        assessed_mitigations = [m for m in mitigation_evidence if m["evidence_status"] != "UNASSESSED"]
        has_gap = any(m["evidence_status"] == "NOT_DETECTED" for m in assessed_mitigations)
        has_control_evidence = any(m["evidence_status"] in {"DETECTED", "PARTIAL"} for m in assessed_mitigations)

        if mapped_risks:
            status = "EVIDENCE_CHAIN"
        elif relevant and has_gap:
            status = "CONTROL_GAP"
        elif relevant and has_control_evidence:
            status = "CONTROL_EVIDENCE"
        elif relevant:
            status = "RELEVANT_UNASSESSED"
        else:
            status = "NOT_OBSERVED"
        counts[status] += 1

        rows.append(
            {
                "id": class_id,
                "name": attack_class.get("name"),
                "family": attack_class.get("family"),
                "protocols": class_protocols,
                "matched_protocols": matched_protocols,
                "evidence_tier": attack_class.get("evidenceTier"),
                "catalog_decision": attack_class.get("decision"),
                "assessment_status": status,
                "attack_detection": "NOT_PERFORMED",
                "mapped_risks": mapped_risks,
                "mitigation_evidence": mitigation_evidence,
                "limitations": (
                    "Vibe maps repository evidence to this ASI row; it does not prove the attack "
                    "exists, is exploitable, or is prevented."
                ),
            }
        )

    metadata = catalog.get("metadata", {})
    return {
        "schema_version": SCHEMA_VERSION,
        "repository": report.metadata.get("repository"),
        "assessment_completeness": report.metadata.get("assessment_completeness"),
        "catalog_source": catalog.get("source"),
        "catalog_version": metadata.get("version") if isinstance(metadata, dict) else None,
        "catalog_status": metadata.get("status") if isinstance(metadata, dict) else None,
        "detected_protocols": protocols,
        "summary": {
            "class_count": len(rows),
            **counts,
        },
        "classes": rows,
        "limitations": [
            "This is a static repository-evidence mapping, not runtime attack detection.",
            "NOT_OBSERVED means Vibe did not observe a matching protocol/evidence bridge; it does not mean the class is impossible.",
            "CONTROL_EVIDENCE means related control evidence exists; it does not establish mitigation effectiveness or ASI validation.",
            "Only explicit Vibe-to-ASI bridges are used; unsupported ASI rows remain relevant/unassessed rather than receiving synthetic confidence.",
        ],
    }
