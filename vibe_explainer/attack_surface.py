"""AI attack-surface representation.

Groups AIFinding objects from ai_discovery.py into the six standard buckets
(Inputs / Model / Retrieval / Tools / Outputs / Storage) and attaches a short,
static security-relevance note to each item.

This is attack-surface *discovery*, not penetration testing: it says what's
there and why it matters, never whether it's exploitable. Exploitability is
explicitly out of scope here — that's the future Aletheia AI Red Team's job.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .ai_discovery import AIFinding, DiscoveryResult
from .dataflow import DataFlowGraph, build_dataflow

BUCKETS = ("inputs", "model", "retrieval", "tools", "outputs", "storage")

# category -> default bucket. A couple of categories are context-dependent
# (see _bucket_for below) and get resolved per-finding instead of by a flat map.
_CATEGORY_BUCKET = {
    "model_provider": "model",
    "ai_usage": "model",
    "prompt_surface": "inputs",
    "rag_retrieval": "retrieval",
    "tool_agent": "tools",
    "mcp": "tools",
    "secret_config": "storage",
}

# Short, static (non-exploitability) security-relevance notes, keyed by category
# and refined by name where the generic note isn't specific enough.
_RELEVANCE_BY_CATEGORY = {
    "model_provider": "Establishes which model/provider handles data — determines where prompts and context are sent.",
    "ai_usage": "Marks where the application actually invokes a model — the core input/output boundary to review.",
    "prompt_surface": "User- or template-influenced prompt construction — check whether untrusted input reaches this without sanitization (prompt-injection surface).",
    "rag_retrieval": "Retrieved content is likely concatenated into model context — check for retrieval poisoning / instructions embedded in retrieved documents.",
    "tool_agent": "Model-invoked or agent-invoked action — check authorization scope and whether a human approves high-risk calls.",
    "mcp": "MCP tool/server surface — review the tool's JSON schema, side effects, and whether permissions default-deny.",
    "external_integration": "Outbound call to an external service or store — check what data leaves the trust boundary and whether it's logged.",
    "secret_config": "Credential material or reference — verify it isn't logged, echoed into model context, or committed in plaintext.",
}

_RELEVANCE_OVERRIDES = {
    ("tool_agent", "Shell execution"): "Direct shell/command execution reachable in this file — high blast radius if inputs here trace back to model output or user input.",
    ("tool_agent", "Dynamic code execution"): "eval/exec use — high blast radius if the evaluated string can be influenced by model output or user input.",
    ("secret_config", "Possible hardcoded API key"): "Looks like a literal API key in source rather than an env-var reference — treat as a credential-exposure finding regardless of AI relevance.",
}


@dataclass
class AttackSurfaceItem:
    bucket: str
    category: str
    name: str
    file: str
    line: int
    evidence: str
    confidence: str
    security_relevance: str
    finding_id: str = ""  # traces back to the source AIFinding.id
    context: str = "PRODUCTION"  # Phase 8: file context of the source finding

    def to_dict(self) -> dict[str, Any]:
        return {
            "bucket": self.bucket,
            "category": self.category,
            "name": self.name,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "security_relevance": self.security_relevance,
            "finding_id": self.finding_id,
            "context": self.context,
        }


@dataclass
class AttackSurfaceResult:
    root: str
    items: list[AttackSurfaceItem] = field(default_factory=list)
    # Optional additional representation — Phase 3 data-flow graph over the same
    # findings. Not populated unless build_attack_surface(..., include_dataflow=True)
    # is used; existing buckets/items/behavior are unaffected either way.
    dataflow: DataFlowGraph | None = None

    def by_bucket(self) -> dict[str, list[AttackSurfaceItem]]:
        out: dict[str, list[AttackSurfaceItem]] = {b: [] for b in BUCKETS}
        for item in self.items:
            out[item.bucket].append(item)
        return out

    def to_dict(self) -> dict[str, Any]:
        by_bucket = self.by_bucket()
        d: dict[str, Any] = {
            "root": self.root,
            "buckets": {b: [i.to_dict() for i in items] for b, items in by_bucket.items()},
            "summary": {b: len(items) for b, items in by_bucket.items()},
        }
        if self.dataflow is not None:
            d["dataflow"] = self.dataflow.to_dict()
        return d


def _bucket_for(finding: AIFinding) -> str:
    if finding.category == "external_integration":
        # Webhooks are inbound triggers; everything else in this category is
        # an outbound call the app makes, which behaves like a tool.
        return "inputs" if finding.name == "Webhook handler" else "tools"
    return _CATEGORY_BUCKET.get(finding.category, "tools")


def _relevance_for(finding: AIFinding) -> str:
    override = _RELEVANCE_OVERRIDES.get((finding.category, finding.name))
    if override:
        return override
    return _RELEVANCE_BY_CATEGORY.get(
        finding.category, "AI-relevant component — security relevance not yet categorized."
    )


def build_attack_surface(discovery: DiscoveryResult, *, include_dataflow: bool = False) -> AttackSurfaceResult:
    """Turn a DiscoveryResult into a bucketed AI attack-surface view.

    Note on scope: there is no dedicated "outputs" detector in ai_discovery.py
    yet (that requires tracing model output into a sink, which is Phase 3
    data-flow work). The "outputs" bucket is therefore expected to be empty
    today — that's an honest gap, not a bug, and should not be read as "no
    output-handling risk."

    Pass include_dataflow=True to also attach the Phase 3 data-flow graph
    (see dataflow.py) as an additional representation alongside the buckets.
    Default is False so existing callers/tests see identical behavior.
    """
    result = AttackSurfaceResult(root=discovery.root)
    for finding in discovery.findings:
        result.items.append(
            AttackSurfaceItem(
                bucket=_bucket_for(finding),
                category=finding.category,
                name=finding.name,
                file=finding.file,
                line=finding.line,
                evidence=finding.evidence,
                confidence=finding.confidence,
                security_relevance=_relevance_for(finding),
                finding_id=finding.id,
                context=getattr(finding, "context", "PRODUCTION"),
            )
        )
    if include_dataflow:
        result.dataflow = build_dataflow(discovery)
    return result
