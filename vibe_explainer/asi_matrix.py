"""Deterministically map Vibe Explainer evidence onto Agent Security Index rows.

This is a bridge layer, not a second scanner. It consumes an already-built
``VibeExplainerReport`` plus a *local* ASI export and reports row relevance,
related Vibe evidence, and repository evidence for mitigations Vibe knows how
to recognize. It never claims exploitability, attack presence, mitigation
effectiveness, or ASI validation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"

# Vibe control -> ASI mitigation evidence bridges. These mean only that a Vibe
# control can provide repository evidence relevant to the mitigation.
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

# Keep attack-specific bridges deliberately narrow. Protocol relevance can make
# many more rows applicable, but unsupported rows must remain unassessed.
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
    if isinstance(payload, list):
        return [
            row for row in payload
            if isinstance(row, dict) and str(row.get("id", "")).startswith("AAC-")
        ]
    if not isinstance(payload, dict):
        return []

    for key in ("attackClasses", "attack_classes", "classes"):
        rows = payload.get(key)
        if isinstance(rows, list):
            found = _extract_attack_classes(rows)
            if found:
                return found
    for key in ("catalog", "data", "matrix"):
        found = _extract_attack_classes(payload.get(key))
        if found:
            return found
    return []


def _extract_metadata(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    # ASI's generated combined snapshot uses `catalog`; accept older/generic
    # aliases too so Vibe does not couple to frontend internals.
    for key in ("catalog", "meta", "metadata"):
        value = payload.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _normalize_class(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    # JSON chunks historically used proposedMitigationIds; the current TS-derived
    # combined export uses mitigations. Normalize once at the boundary.
    if "proposedMitigationIds" not in out and isinstance(out.get("mitigations"), list):
        out["proposedMitigationIds"] = list(out["mitigations"])
    return out


def load_asi_catalog(path: str | Path) -> dict[str, Any]:
    """Load a local ASI export directory or JSON file; never fetch the network.

    Directory mode prefers a generated ``asi-catalog.json``. If it is absent,
    split ``attack-classes*.json`` files are accepted only when their observed
    count matches ``catalog-meta.json.classCount`` (when declared). This prevents
    a stale partial export from silently becoming a partial customer matrix.
    """
    source = Path(path)
    metadata: dict[str, Any] = {}
    classes: list[dict[str, Any]] = []

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
            metadata = metadata or _extract_metadata(payload)
        else:
            for fragment in sorted(source.glob("attack-classes*.json")):
                classes.extend(_extract_attack_classes(_load_json(fragment)))
    else:
        payload = _load_json(source)
        classes = _extract_attack_classes(payload)
        metadata = _extract_metadata(payload)

    classes = [_normalize_class(row) for row in classes]
    if not classes:
        raise ValueError(
            "No AAC attack classes found. Provide an ASI export directory, "
            "asi-catalog.json, or attack-classes JSON file."
        )

    ids = [str(row.get("id", "")) for row in classes]
    duplicates = sorted({item for item in ids if ids.count(item) > 1})
    if duplicates:
        raise ValueError(f"Duplicate ASI attack-class IDs: {', '.join(duplicates)}")

    expected_count = metadata.get("classCount") if isinstance(metadata, dict) else None
    if isinstance(expected_count, int) and expected_count > 0 and len(classes) != expected_count:
        raise ValueError(
            f"Incomplete ASI catalog export: metadata declares {expected_count} classes "
            f"but {len(classes)} were loaded. Run `npm run assemble:catalog` in "
            "agent-security-index and point Vibe at the generated export."
        )

    classes.sort(key=lambda row: str(row.get("id", "")))
    return {"metadata": metadata, "classes": classes, "source": str(source)}


def _detected_protocols(report: Any) -> list[str]:
    protocols: set[str] = set()
    categories = report.ai_inventory.get("categories", {})
    if categories.get("ai_usage") or categories.get("tool_agent"):
        protocols.add("Native")
    if categories.get("mcp"):
        protocols.add("MCP")
    if categories.get("rag_retrieval"):
        protocols.add("RAG")

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
                }
    return result


def _mitigation_to_controls() -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for control_id, mitigation_ids in _CONTROL_TO_ASI_MITIGATIONS.items():
        for mitigation_id in mitigation_ids:
            result.setdefault(mitigation_id, []).append(control_id)
    return result


def _best_control_status(
    control_ids: list[str], controls: dict[str, dict[str, Any]]
) -> tuple[str, list[dict[str, Any]]]:
    best = "UNASSESSED"
    best_rank = _STATUS_RANK[best]
    evidence: list[dict[str, Any]] = []
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
        # AAC-16 specifically concerns MCP STDIO; a generic shell path is not enough.
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
    """Map one completed Vibe security report to every loaded ASI class."""
    protocols = _detected_protocols(report)
    protocol_set = set(protocols)
    controls = _control_statuses(report)
    mitigation_controls = _mitigation_to_controls()
    ai_surface_detected = report.executive_summary.get("ai_surface") == "DETECTED"

    counts = {
        "EVIDENCE_CHAIN": 0,
        "CONTROL_GAP": 0,
        "CONTROL_EVIDENCE": 0,
        "RELEVANT_UNASSESSED": 0,
        "NOT_OBSERVED": 0,
    }
    rows: list[dict[str, Any]] = []

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
            status, control_evidence = _best_control_status(
                mitigation_controls.get(mitigation_id, []), controls
            )
            mitigation_evidence.append(
                {
                    "mitigation_id": mitigation_id,
                    "evidence_status": status,
                    "mapped_controls": control_evidence,
                    "note": "Repository evidence only; this does not validate ASI mitigation effectiveness.",
                }
            )

        assessed = [m for m in mitigation_evidence if m["evidence_status"] != "UNASSESSED"]
        has_gap = any(m["evidence_status"] == "NOT_DETECTED" for m in assessed)
        has_control = any(m["evidence_status"] in {"DETECTED", "PARTIAL"} for m in assessed)

        if mapped_risks:
            status = "EVIDENCE_CHAIN"
        elif relevant and has_gap:
            status = "CONTROL_GAP"
        elif relevant and has_control:
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
                "family": attack_class.get("family") or attack_class.get("vector"),
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
        "summary": {"class_count": len(rows), **counts},
        "classes": rows,
        "limitations": [
            "This is a static repository-evidence mapping, not runtime attack detection.",
            "NOT_OBSERVED means Vibe did not observe a matching protocol/evidence bridge; it does not mean the class is impossible.",
            "CONTROL_EVIDENCE means related control evidence exists; it does not establish mitigation effectiveness or ASI validation.",
            "Only explicit Vibe-to-ASI bridges are used; unsupported ASI rows remain relevant/unassessed rather than receiving synthetic confidence.",
        ],
    }
