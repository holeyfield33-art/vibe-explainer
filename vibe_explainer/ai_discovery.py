"""AI component discovery — static, content-level scan for AI-relevant evidence.

Extends the offline structural pass in ``scanner.py`` (which only sees filenames
and line counts) with pattern matching over file *content* to surface evidence of
AI/LLM usage: providers, prompt surfaces, retrieval, tools/agents, MCP, external
integrations, and secret/config handling.

This is discovery, not proof. Every finding carries a confidence level and the
literal evidence line it was matched from — never claim certainty from a single
keyword hit. No network calls, no LLM calls: regex over text the scanner already
has access to.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .scanner import SKIP_DIRS

# Extensions worth content-scanning for AI evidence. Broader than scanner.CODE_EXTS
# because config/env files are where secrets and MCP transport config tend to live.
SCAN_EXTS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".rs",
    ".java",
    ".rb",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".env",
    ".cfg",
    ".ini",
}

MAX_FILE_BYTES = 500_000  # skip anything larger; not built to profile huge files
MAX_FINDINGS_PER_FILE_PATTERN = 3  # cap repeated hits so one noisy file doesn't dominate

Confidence = str  # "high" | "moderate" | "low"


def _finding_id(file: str, line: int, category: str, name: str) -> str:
    """Deterministic short ID so later phases (data-flow, controls) can reference
    a specific finding without re-deriving identity from its fields. Stable across
    runs on unchanged code; changes only if the underlying match moves/changes."""
    digest = hashlib.sha1(f"{file}:{line}:{category}:{name}".encode("utf-8")).hexdigest()
    return digest[:12]


@dataclass
class AIFinding:
    category: str  # model_provider | ai_usage | prompt_surface | rag_retrieval |
    #                tool_agent | mcp | external_integration | secret_config
    name: str
    file: str
    line: int
    evidence: str
    confidence: Confidence
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            self.id = _finding_id(self.file, self.line, self.category, self.name)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "name": self.name,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "confidence": self.confidence,
        }


@dataclass
class TruncatedGroup:
    """Records that a (file, category, name) group hit MAX_FINDINGS_PER_FILE_PATTERN
    and additional matches beyond the cap were not turned into findings."""

    file: str
    category: str
    name: str
    additional_matches: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "category": self.category,
            "name": self.name,
            "additional_matches": self.additional_matches,
        }


@dataclass
class DiscoveryResult:
    root: str
    findings: list[AIFinding] = field(default_factory=list)
    files_scanned: int = 0
    truncated: list[TruncatedGroup] = field(default_factory=list)

    def by_category(self) -> dict[str, list[AIFinding]]:
        out: dict[str, list[AIFinding]] = {}
        for f in self.findings:
            out.setdefault(f.category, []).append(f)
        return out

    def has_ai_signal(self) -> bool:
        return len(self.findings) > 0

    def to_dict(self) -> dict[str, Any]:
        by_cat = self.by_category()
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "has_ai_signal": self.has_ai_signal(),
            "findings": [f.to_dict() for f in self.findings],
            "summary": {cat: len(items) for cat, items in by_cat.items()},
            "truncated": [t.to_dict() for t in self.truncated],
        }


# ---------------------------------------------------------------------------
# Pattern table: (category, name, compiled regex, confidence)
#
# "high" = specific SDK import / API call / distinctive identifier, low false-
#          positive risk in isolation.
# "moderate" = plausible but more generic signal (bare product-name mention,
#          common function name that could collide with non-AI code).
# "low" = weak keyword-only signal; kept because absence-of-evidence claims are
#          worse than a flagged-but-uncertain hit, but never treated as proof.
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[str, str, re.Pattern[str], Confidence]] = [
    # --- MODEL PROVIDERS -----------------------------------------------
    ("model_provider", "OpenAI", re.compile(r"\b(?:import\s+openai|from\s+openai\s+import|OpenAI\()"), "high"),
    ("model_provider", "OpenAI", re.compile(r"\bopenai\b", re.IGNORECASE), "low"),
    ("model_provider", "Anthropic", re.compile(r"\b(?:import\s+anthropic|from\s+anthropic\s+import|Anthropic\()"), "high"),
    ("model_provider", "Anthropic", re.compile(r"\bclaude-[a-z0-9.\-]+\b", re.IGNORECASE), "high"),
    ("model_provider", "Google/Gemini", re.compile(r"(?:google\.generativeai|from\s+google\s+import\s+genai|GenerativeModel\()"), "high"),
    ("model_provider", "Google/Gemini", re.compile(r"\bgemini\b", re.IGNORECASE), "low"),
    ("model_provider", "Azure OpenAI", re.compile(r"\bAzureOpenAI\(|azure\.ai\.openai"), "high"),
    ("model_provider", "Ollama", re.compile(r"\b(?:import\s+ollama|from\s+ollama\s+import|ollama\.chat\()"), "high"),
    ("model_provider", "Ollama", re.compile(r"\bollama\b", re.IGNORECASE), "low"),
    ("model_provider", "Hugging Face", re.compile(r"\b(?:from\s+transformers\s+import|import\s+transformers|huggingface_hub|AutoModel(?:ForCausalLM)?\()"), "high"),
    ("model_provider", "Cohere", re.compile(r"\b(?:import\s+cohere|from\s+cohere\s+import)\b"), "high"),
    ("model_provider", "Mistral", re.compile(r"\b(?:mistralai|MistralClient)\b"), "moderate"),
    # --- AI USAGE ---------------------------------------------------------
    ("ai_usage", "Chat/completions call", re.compile(r"\.(?:chat\.completions|messages)\.create\("), "high"),
    ("ai_usage", "Embeddings call", re.compile(r"\.embeddings\.create\(|\.embed\("), "high"),
    ("ai_usage", "LangChain", re.compile(r"\b(?:import\s+langchain|from\s+langchain)"), "high"),
    ("ai_usage", "LlamaIndex", re.compile(r"\b(?:import\s+llama_index|from\s+llama_index)"), "high"),
    ("ai_usage", "Agent framework", re.compile(r"\b(?:AgentExecutor|create_agent|initialize_agent)\("), "moderate"),
    # --- PROMPT SURFACES ----------------------------------------------------
    ("prompt_surface", "System prompt variable", re.compile(r"\b(?:SYSTEM_PROMPT|system_prompt|systemPrompt)\b\s*[:=]"), "high"),
    ("prompt_surface", "Prompt template", re.compile(r"\bPromptTemplate\(|prompt_template\s*[:=]"), "moderate"),
    ("prompt_surface", "Generic prompt variable", re.compile(r"\b(?:prompt|PROMPT)\b\s*[:=]\s*(?:f?[\"'])"), "low"),
    # --- RAG / RETRIEVAL ----------------------------------------------------
    ("rag_retrieval", "Pinecone", re.compile(r"\bpinecone\b", re.IGNORECASE), "high"),
    ("rag_retrieval", "Weaviate", re.compile(r"\bweaviate\b", re.IGNORECASE), "high"),
    ("rag_retrieval", "Chroma", re.compile(r"\bchromadb\b|\bChroma\("), "high"),
    ("rag_retrieval", "Qdrant", re.compile(r"\bqdrant\b", re.IGNORECASE), "high"),
    ("rag_retrieval", "FAISS", re.compile(r"\bfaiss\b", re.IGNORECASE), "high"),
    ("rag_retrieval", "Milvus", re.compile(r"\bmilvus\b", re.IGNORECASE), "high"),
    ("rag_retrieval", "Vector store / retriever", re.compile(r"\b(?:VectorStore|similarity_search|as_retriever)\("), "moderate"),
    # --- TOOLS / AGENTS -------------------------------------------------
    ("tool_agent", "Tool/function decorator", re.compile(r"@tool\b|@function_tool\b"), "high"),
    ("tool_agent", "Function-calling config", re.compile(r"\b(?:tool_choice|function_call)\s*[:=]"), "moderate"),
    ("tool_agent", "Shell execution", re.compile(r"\b(?:subprocess\.(?:run|Popen|call)|os\.system|os\.popen)\("), "high"),
    # Guard against JS false positives: `.exec(` is a method call (regex.exec,
    # child.exec via a member) and JS `re.exec(str)` is a regex match, not code
    # execution. Require eval/exec NOT preceded by a dot, and for exec require it
    # to look like a bare call. This still catches Python eval(/exec( and bare
    # exec( / eval(, but not `foo.exec(` or `re.exec(`.
    ("tool_agent", "Dynamic code execution", re.compile(r"(?<![.\w])(?:eval|exec)\("), "moderate"),
    # --- MCP ----------------------------------------------------------------
    ("mcp", "MCP SDK", re.compile(r"\bmodelcontextprotocol\b|\bfrom\s+mcp\s+import|\bimport\s+mcp\b"), "high"),
    ("mcp", "FastMCP server", re.compile(r"\bFastMCP\(|@mcp\.tool\b|@mcp\.resource\b"), "high"),
    ("mcp", "MCP client session", re.compile(r"\bClientSession\(|StdioServerParameters\("), "high"),
    ("mcp", "MCP server config", re.compile(r"\"mcpServers\"|'mcpServers'|mcp_servers\s*[:=]"), "high"),
    # --- EXTERNAL INTEGRATIONS ------------------------------------------
    ("external_integration", "HTTP client call", re.compile(r"\b(?:requests\.(?:get|post|put|delete)|httpx\.(?:get|post|put|delete))\("), "moderate"),
    ("external_integration", "Webhook", re.compile(r"\bwebhook\b", re.IGNORECASE), "low"),
    ("external_integration", "SQL database client", re.compile(r"\b(?:psycopg2|sqlalchemy|pymongo)\b"), "moderate"),
    ("external_integration", "Redis client", re.compile(r"\bredis\.(?:Redis|StrictRedis)\("), "moderate"),
    # --- SECRETS / CONFIGURATION -----------------------------------------
    ("secret_config", "Model API key env var", re.compile(r"\b(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|AZURE_OPENAI_KEY|HUGGINGFACE_TOKEN|COHERE_API_KEY|GOOGLE_API_KEY)\b"), "high"),
    ("secret_config", "Possible hardcoded API key", re.compile(r"sk-[A-Za-z0-9_-]{20,}"), "high"),
    ("secret_config", "Generic API key reference", re.compile(r"\bAPI_KEY\b\s*[:=]"), "low"),
]


def _should_skip_dir(name: str) -> bool:
    return name in SKIP_DIRS or name.startswith(".")


def _iter_candidate_files(root_path: Path):
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(d)]
        for name in filenames:
            full = Path(dirpath) / name
            if full.suffix.lower() not in SCAN_EXTS:
                continue
            yield full


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
    except OSError:
        return None
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def discover_ai(root: str | Path) -> DiscoveryResult:
    """Scan *root* for content-level evidence of AI components.

    Static text matching only. A finding means "this pattern appears in this
    file" — not "this code definitely does X". Confidence reflects how specific
    the matched pattern is, not how the code behaves at runtime.
    """
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    result = DiscoveryResult(root=str(root_path))
    # per-(file, category, name) counter to cap noisy repeats
    seen_counts: dict[tuple[str, str, str], int] = {}
    # (file, category, name) is not a unique key: two different patterns (e.g. a
    # specific high-confidence one and a generic low-confidence keyword one) can
    # both match the same line, which would otherwise produce two AIFinding
    # objects sharing the same id. Track by id so that case upgrades confidence
    # in place instead of creating a duplicate identity.
    index_by_id: dict[str, int] = {}
    truncated_ids: set[str] = set()  # (file,line,category,name) identities already counted as truncated
    _CONFIDENCE_PRIORITY = {"high": 3, "moderate": 2, "low": 1}

    for file_path in _iter_candidate_files(root_path):
        text = _read_text(file_path)
        if text is None:
            continue
        result.files_scanned += 1
        rel = str(file_path.relative_to(root_path)).replace("\\", "/")

        for category, name, pattern, confidence in _PATTERNS:
            for match in pattern.finditer(text):
                line_no = text.count("\n", 0, match.start()) + 1
                fid = _finding_id(rel, line_no, category, name)

                if fid in index_by_id:
                    # same (file, line, category, name) identity already
                    # recorded by another pattern — upgrade confidence if this
                    # match is more specific, but never create a second finding
                    # for the same identity, and don't count it against the
                    # noise cap (it isn't additional evidence, just a second
                    # pattern confirming the same spot).
                    existing = result.findings[index_by_id[fid]]
                    if _CONFIDENCE_PRIORITY[confidence] > _CONFIDENCE_PRIORITY[existing.confidence]:
                        existing.confidence = confidence
                    continue

                key = (rel, category, name)
                count = seen_counts.get(key, 0)
                if count >= MAX_FINDINGS_PER_FILE_PATTERN:
                    if fid in truncated_ids:
                        # same (file, line, category, name) identity already
                        # counted as truncated by another pattern — don't
                        # inflate additional_matches with redundant re-hits of
                        # the exact same line.
                        continue
                    truncated_ids.add(fid)
                    seen_counts[key] = count + 1
                    # record (or bump) the truncation instead of silently
                    # dropping the match entirely
                    for t in result.truncated:
                        if (t.file, t.category, t.name) == key:
                            t.additional_matches += 1
                            break
                    else:
                        result.truncated.append(
                            TruncatedGroup(file=rel, category=category, name=name, additional_matches=1)
                        )
                    continue
                seen_counts[key] = count + 1

                line_start = text.rfind("\n", 0, match.start()) + 1
                line_end = text.find("\n", match.start())
                if line_end == -1:
                    line_end = len(text)
                evidence = text[line_start:line_end].strip()
                if len(evidence) > 160:
                    evidence = evidence[:157] + "..."

                effective_confidence = confidence
                # Match-context guard: a dangerous-call token (eval/exec/shell) that
                # sits inside a string literal or a comment is very likely a
                # detection signature, an example, or documentation prose — not a
                # live call. Downgrade confidence rather than dropping the finding
                # (no silent drops), so a security tool's own signature strings
                # don't read as production code execution.
                if name in _SIGNATURE_PRONE_NAMES and _match_in_string_or_comment(text, match.start(), line_start):
                    effective_confidence = "low"

                index_by_id[fid] = len(result.findings)
                result.findings.append(
                    AIFinding(
                        category=category,
                        name=name,
                        file=rel,
                        line=line_no,
                        evidence=evidence,
                        confidence=effective_confidence,
                    )
                )

    return result


# Pattern names most prone to string-literal / comment false positives (a security
# tool scanning FOR these tokens will have them as literals/comments in its source).
_SIGNATURE_PRONE_NAMES = frozenset({"Dynamic code execution", "Shell execution"})


def _match_in_string_or_comment(text: str, match_start: int, line_start: int) -> bool:
    """Best-effort check: is the match position inside a quoted string or after a
    line-comment marker on its own line? Line-scoped and language-agnostic — not a
    real parser, deliberately conservative (only flags clear cases)."""
    prefix = text[line_start:match_start]
    # line comment before the match (# for py/sh, // for js/ts)
    if "#" in prefix or "//" in prefix:
        return True
    # odd number of unescaped quotes before the match => inside a string literal
    for q in ("'", '"', "`"):
        # ignore escaped quotes
        count = len(re.findall(r"(?<!\\)" + re.escape(q), prefix))
        if count % 2 == 1:
            return True
    return False
