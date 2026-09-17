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

import ast
import hashlib
import io
import os
import re
import stat
import time
import tokenize
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .exclusion_policy import walk_pruned
from .scan_budget import ACTIVE, within_budget
from .file_context import classify_file
from .security_utils import minimal_match_excerpt

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

# Global scan budgets (issue #21/#9): without these, a hostile or accidental
# tree of tens of thousands of tiny files can exhaust memory/time on the scan
# host. Hitting any of these stops the walk early rather than running
# unbounded — the caller is told via budget_exhausted so completeness can be
# marked PARTIAL instead of silently claiming full coverage.
MAX_FILES_SCANNED = 20_000
MAX_TOTAL_BYTES = 200_000_000
MAX_SCAN_SECONDS = 120.0

Confidence = str  # "high" | "moderate" | "low"


def _finding_id(
    file: str, line: int, category: str, name: str, *, stable_locator: str | None = None
) -> str:
    """Deterministic short ID so later phases (data-flow, controls) can reference
    a specific finding without re-deriving identity from its fields. Stable across
    runs on unchanged code. Scanned findings use a stable per-signal occurrence
    locator so unrelated line insertions do not churn identity; direct callers
    retain line-based compatibility."""
    locator = stable_locator if stable_locator is not None else f"line:{line}"
    digest = hashlib.sha1(f"{file}:{locator}:{category}:{name}".encode("utf-8")).hexdigest()
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
    context: str = "PRODUCTION"  # file context (Phase 8D): PRODUCTION/TEST/SECURITY_TEST/...
    context_confidence: str = "moderate"
    context_defaulted: bool = False
    evidence_basis: str = "PYTHON_AST"
    supports_conclusions: bool = True

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
            "context": self.context,
            "context_confidence": self.context_confidence,
            "context_defaulted": self.context_defaulted,
            "evidence_basis": self.evidence_basis,
            "supports_conclusions": self.supports_conclusions,
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
    # Phase 8G: file -> list of repo-relative files it imports (resolved via AST/
    # regex import resolution). Only repo-internal imports appear here; external
    # packages are excluded. Used to build cross-file dataflow edges.
    imports_by_file: dict[str, list[str]] = field(default_factory=dict)
    # Coverage-gap counters (issue #20/#21/#9): a candidate file that was in
    # scope but never examined, distinct from "no evidence found in an examined
    # file". Any of these being non-zero means completeness must be PARTIAL,
    # not COMPLETE — see risk.py's assessment_completeness computation.
    files_skipped_size: int = 0
    files_unreadable: int = 0
    budget_exhausted: bool = False
    budget_exhausted_reason: str | None = None
    supported_languages: list[str] = field(default_factory=lambda: ["python", "structured_config"])
    supported_constructs: list[str] = field(default_factory=lambda: [
        "python imports", "python calls", "python assignments", "python decorators",
        "JSON/YAML/TOML/env configuration artifacts",
    ])

    def by_category(self) -> dict[str, list[AIFinding]]:
        out: dict[str, list[AIFinding]] = {}
        for f in self.findings:
            out.setdefault(f.category, []).append(f)
        return out

    def has_ai_signal(self) -> bool:
        return bool(self.conclusion_findings())

    def has_any_lead(self) -> bool:
        return bool(self.findings)

    def conclusion_findings(self) -> list[AIFinding]:
        """Evidence eligible for risk, control, and readiness conclusions."""
        return [f for f in self.findings if f.supports_conclusions]

    def has_coverage_gap(self) -> bool:
        return self.files_skipped_size > 0 or self.files_unreadable > 0 or self.budget_exhausted

    def to_dict(self) -> dict[str, Any]:
        by_cat = self.by_category()
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "has_ai_signal": self.has_ai_signal(),
            "findings": [f.to_dict() for f in self.findings],
            "analysis_coverage": {
                "supported_languages": self.supported_languages,
                "supported_constructs": self.supported_constructs,
                "authoritative_findings": len(self.conclusion_findings()),
                "unsupported_lexical_leads": sum(
                    1 for f in self.findings if f.evidence_basis == "LEXICAL_LEAD"
                ),
                "unresolved_findings": sum(
                    1 for f in self.findings if f.evidence_basis.startswith("UNRESOLVED_")
                ),
                "note": (
                    "Python findings are syntax-gated and configuration artifacts are lexical. "
                    "Other-language matches are leads only and cannot drive conclusions."
                ),
            },
            "summary": {cat: len(items) for cat, items in by_cat.items()},
            "truncated": [t.to_dict() for t in self.truncated],
            "files_skipped_size": self.files_skipped_size,
            "files_unreadable": self.files_unreadable,
            "budget_exhausted": self.budget_exhausted,
            "budget_exhausted_reason": self.budget_exhausted_reason,
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
    # TS/JS idioms — modern apps call models via raw fetch to the provider endpoint
    # or via the Vercel AI SDK, not the Python-style SDK. These are the highest-value
    # additions found on the creator-ai-hub validation run.
    ("ai_usage", "OpenAI-compatible HTTP endpoint", re.compile(r"api\.openai\.com/v1|/v1/chat/completions|/chat/completions\b"), "high"),
    ("ai_usage", "Whisper transcription endpoint", re.compile(r"\bwhisper-1\b|/audio/transcriptions\b"), "high"),
    ("ai_usage", "Vercel AI SDK call", re.compile(r"\b(?:generateText|streamText|generateObject|streamObject)\s*\(|@ai-sdk/"), "high"),
    ("ai_usage", "Chat messages array", re.compile(r"\bmessages\s*:\s*\[\s*\{\s*role\s*:"), "moderate"),
    # --- PROMPT SURFACES ----------------------------------------------------
    ("prompt_surface", "System prompt variable", re.compile(r"\b(?:SYSTEM_PROMPT|system_prompt|systemPrompt)\b\s*[:=]"), "high"),
    ("prompt_surface", "Prompt template", re.compile(r"\bPromptTemplate\(|prompt_template\s*[:=]"), "moderate"),
    ("prompt_surface", "Chat role message", re.compile(r"\brole\s*:\s*['\"](?:system|user|assistant)['\"]"), "moderate"),
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
    # Webhook: the bare word matched fixture names, regex patterns, and corpus
    # descriptions across every validation repo (16 hits, 0 real). Require an
    # actual webhook handler/registration idiom instead of the bare noun.
    ("external_integration", "Webhook handler", re.compile(r"(?i)\b(?:on_webhook|handle_webhook|webhook_handler|register_webhook|@webhook)\b|\bapp\.(?:post|route)\(['\"][^'\"]*webhook"), "moderate"),
    ("external_integration", "SQL database client", re.compile(r"\b(?:psycopg2|sqlalchemy|pymongo)\b"), "moderate"),
    ("external_integration", "Redis client", re.compile(r"\bredis\.(?:Redis|StrictRedis)\("), "moderate"),
    # --- SECRETS / CONFIGURATION -----------------------------------------
    ("secret_config", "Model API key env var", re.compile(r"\b(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|AZURE_OPENAI_KEY|HUGGINGFACE_TOKEN|COHERE_API_KEY|GOOGLE_API_KEY|AI_API_KEY|AI_MODEL|AI_BASE_URL)\b"), "high"),
    ("secret_config", "Possible hardcoded API key", re.compile(r"sk-[A-Za-z0-9_-]{20,}"), "high"),
    ("secret_config", "Generic API key reference", re.compile(r"\bAPI_KEY\b\s*[:=]"), "low"),
    # Custom-named credential env vars (e.g. AEGIS_EVAL_API_KEY) that the fixed
    # provider-name list and the bare-word "API_KEY" pattern both miss — this
    # catches the access idiom (process.env./os.environ/os.getenv) rather than
    # a specific name, independent of provider.
    (
        "secret_config",
        "Env-based credential reference",
        re.compile(
            r"\bprocess\.env\.\w*(?:API_KEY|TOKEN|SECRET|CREDENTIAL)\w*\b"
            r"|\bos\.environ(?:\.get)?\s*[\[\(]\s*['\"]\w*(?:API_KEY|TOKEN|SECRET|CREDENTIAL)\w*['\"]"
            r"|\bos\.getenv\(\s*['\"]\w*(?:API_KEY|TOKEN|SECRET|CREDENTIAL)\w*['\"]",
            re.IGNORECASE,
        ),
        "moderate",
    ),
]

_CONFIG_EXTS = frozenset({".json", ".yaml", ".yml", ".toml", ".env", ".cfg", ".ini"})
_PY_STRUCTURAL_NODES = (
    ast.Import, ast.ImportFrom, ast.Call, ast.Assign, ast.AnnAssign, ast.NamedExpr,
    ast.FunctionDef, ast.AsyncFunctionDef,
)
_PY_STRING_ALLOWED_NAMES = frozenset({
    "System prompt variable", "Prompt template", "Generic prompt variable",
    "Model API key env var", "Possible hardcoded API key", "Generic API key reference",
    "Env-based credential reference", "OpenAI-compatible HTTP endpoint",
    "Whisper transcription endpoint", "MCP server config", "Function-calling config",
    "Chat role message", "Chat messages array",
})


@dataclass(frozen=True)
class _PythonSyntax:
    parsed: bool
    structural_spans: tuple[tuple[int, int, int, int], ...] = ()
    comment_spans: tuple[tuple[int, int, int, int], ...] = ()
    string_spans: tuple[tuple[int, int, int, int], ...] = ()
    unresolved_spans: tuple[tuple[int, int, int, int], ...] = ()


def _contains(span: tuple[int, int, int, int], line: int, column: int) -> bool:
    sl, sc, el, ec = span
    return (line, column) >= (sl, sc) and (line, column) < (el, ec)


def _python_syntax(text: str) -> _PythonSyntax:
    comments: list[tuple[int, int, int, int]] = []
    strings: list[tuple[int, int, int, int]] = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            span = (token.start[0], token.start[1], token.end[0], token.end[1])
            if token.type == tokenize.COMMENT:
                comments.append(span)
            elif token.type == tokenize.STRING:
                strings.append(span)
    except (tokenize.TokenError, IndentationError):
        pass
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return _PythonSyntax(False, comment_spans=tuple(comments), string_spans=tuple(strings))
    spans_list = [
        (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)
        for node in ast.walk(tree)
        if isinstance(node, _PY_STRUCTURAL_NODES)
        and hasattr(node, "end_lineno")
        and node.end_lineno is not None
    ]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            spans_list.extend(
                (decorator.lineno, max(0, decorator.col_offset - 1), decorator.end_lineno, decorator.end_col_offset)
                for decorator in node.decorator_list
                if getattr(decorator, "end_lineno", None) is not None
            )
    unresolved: list[tuple[int, int, int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and isinstance(node.test, ast.Constant) and not node.test.value:
            unresolved.extend(
                (child.lineno, child.col_offset, child.end_lineno, child.end_col_offset)
                for child in node.body
                if getattr(child, "end_lineno", None) is not None
            )
    return _PythonSyntax(
        True, tuple(spans_list), tuple(comments), tuple(strings), tuple(unresolved)
    )


_SUPPORTED_TOOL_IMPORTS = frozenset({
    "langchain.tools",
    "langchain_core.tools",
})
_SUPPORTED_RETRIEVER_IMPORTS = frozenset({
    "langchain_chroma",
})


def _python_symbol_provenance(text: str) -> tuple[set[str], dict[str, str]]:
    """Return supported tool names and provenance-backed retriever instances.

    These deliberately bounded facts prevent a generic ``@tool`` decorator or
    ``obj.similarity_search()`` method from becoming authoritative merely because
    its spelling resembles an AI framework API.
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return set(), {}

    tool_names: set[str] = set()
    retriever_constructors: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or not node.module:
            continue
        if node.module in _SUPPORTED_TOOL_IMPORTS:
            for alias in node.names:
                if alias.name in {"tool", "function_tool"}:
                    tool_names.add(alias.asname or alias.name)
        if node.module in _SUPPORTED_RETRIEVER_IMPORTS:
            for alias in node.names:
                if alias.name == "Chroma":
                    retriever_constructors.add(alias.asname or alias.name)

    retriever_instances: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Name):
            continue
        if value.func.id not in retriever_constructors:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                retriever_instances[target.id] = value.func.id
    return tool_names, retriever_instances


def _has_supported_symbol_provenance(
    text: str, match_start: int, name: str
) -> bool:
    tool_names, retriever_instances = _python_symbol_provenance(text)
    before = text[:match_start]
    if name == "Tool/function decorator":
        match = re.match(r"@([A-Za-z_]\w*)", text[match_start:])
        return bool(match and match.group(1) in tool_names)
    if name == "Vector store / retriever" and text.startswith("similarity_search", match_start):
        receiver = re.search(r"([A-Za-z_]\w*)\.\s*$", before)
        return bool(receiver and receiver.group(1) in retriever_instances)
    return True


def _classify_match_basis(
    suffix: str, syntax: _PythonSyntax | None, text: str, match_start: int, name: str
) -> tuple[str, bool] | None:
    """Classify evidence, dropping Python comments and inert code-like strings."""
    if suffix != ".py":
        if suffix in _CONFIG_EXTS:
            return "CONFIG_ARTIFACT", True
        return "LEXICAL_LEAD", False
    assert syntax is not None
    before = text[:match_start]
    line = before.count("\n") + 1
    column = match_start - (before.rfind("\n") + 1)
    if any(_contains(span, line, column) for span in syntax.comment_spans):
        return "LEXICAL_LEAD", False
    in_string = any(_contains(span, line, column) for span in syntax.string_spans)
    if not syntax.parsed:
        return "UNRESOLVED_PARSE", False
    if any(_contains(span, line, column) for span in syntax.unresolved_spans):
        return "UNRESOLVED_STATIC", False
    positions = (column, column + 1) if name == "Tool/function decorator" else (column,)
    if not any(
        _contains(span, line, candidate) for span in syntax.structural_spans for candidate in positions
    ):
        return None
    if in_string and name not in _PY_STRING_ALLOWED_NAMES:
        return None
    if name in {"Tool/function decorator", "Vector store / retriever"} and not (
        _has_supported_symbol_provenance(text, match_start, name)
    ):
        return "UNRESOLVED_SYMBOL", False
    return "PYTHON_AST", True


def _iter_candidate_files(root_path: Path):
    for dirpath, dirnames, filenames in walk_pruned(root_path):
        for name in filenames:
            if not within_budget():
                return
            full = Path(dirpath) / name
            if _scan_suffix(full) not in SCAN_EXTS:
                if ACTIVE.get():
                    ACTIVE.get().unsupported.add(_scan_suffix(full) or "(no extension)")
                continue
            yield full


def _scan_suffix(path: Path) -> str:
    """Return the scan type, including dotfiles for which Path.suffix is empty."""
    return ".env" if path.name == ".env" else path.suffix.lower()


def _read_text_with_reason(path: Path) -> tuple[str | None, str | None]:
    """Read one bounded regular file without following a final symlink.

    Repositories are untrusted input. Refusing symlinks and special files prevents
    out-of-scope reads and blocking on FIFOs/devices. ``O_NOFOLLOW`` also closes the
    common check/open race on platforms that provide it.

    Returns ``(text, None)`` on success, or ``(None, reason)`` where ``reason`` is
    ``"oversized"`` (skipped by size, not a coverage failure of the file itself) or
    ``"unreadable"`` (not a regular file, or a genuine read/stat failure) — so the
    caller can count *why* a candidate was never examined instead of only knowing
    that it wasn't.
    """
    budget = ACTIVE.get()
    if budget and not budget.check():
        return None, "budget"
    try:
        metadata = path.lstat()
    except OSError:
        return None, "unreadable"
    if not stat.S_ISREG(metadata.st_mode):
        return None, "unreadable"
    if budget and not budget.admit(path, metadata.st_size):
        return None, "budget"
    if metadata.st_size > MAX_FILE_BYTES:
        return None, "oversized"
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            chunks: list[bytes] = []
            remaining = MAX_FILE_BYTES + 1
            while remaining > 0:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
        finally:
            os.close(fd)
        if len(data) > MAX_FILE_BYTES:
            return None, "oversized"
        if budget:
            if not budget.admit(path, len(data)):
                return None, "budget"
            budget.record_read(path, len(data))
        return data.decode("utf-8", errors="ignore"), None
    except OSError:
        return None, "unreadable"


def _read_text(path: Path) -> str | None:
    text, _reason = _read_text_with_reason(path)
    return text


def discover_ai(
    root: str | Path,
    *,
    excluded_paths: set[str] | frozenset[str] | None = None,
) -> DiscoveryResult:
    """Scan *root* for content-level evidence of AI components.

    Static text matching only. A finding means "this pattern appears in this
    file" — not "this code definitely does X". Confidence reflects how specific
    the matched pattern is, not how the code behaves at runtime.
    """
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    result = DiscoveryResult(root=str(root_path))
    excluded = {p.replace("\\", "/").removeprefix("./") for p in (excluded_paths or ())}
    # per-(file, category, name) counter to cap noisy repeats
    seen_counts: dict[tuple[str, str, str], int] = {}
    # (file, category, name) is not a unique key: two different patterns (e.g. a
    # specific high-confidence one and a generic low-confidence keyword one) can
    # both match the same line, which would otherwise produce two AIFinding
    # objects sharing the same id. Track by id so that case upgrades confidence
    # in place instead of creating a duplicate identity.
    index_by_id: dict[str, int] = {}
    location_ids: dict[tuple[str, int, str, str], str] = {}
    signal_occurrences: dict[tuple[str, str, str], int] = {}
    truncated_ids: set[str] = set()  # (file,line,category,name) identities already counted as truncated
    _CONFIDENCE_PRIORITY = {"high": 3, "moderate": 2, "low": 1}
    file_texts: dict[str, str] = {}  # rel -> content, for Phase 8G import resolution

    start_time = time.monotonic()
    total_bytes_read = 0

    for file_path in _iter_candidate_files(root_path):
        rel = str(file_path.relative_to(root_path)).replace("\\", "/")
        if rel in excluded:
            continue
        if not ACTIVE.get() and result.files_scanned >= MAX_FILES_SCANNED:
            result.budget_exhausted = True
            result.budget_exhausted_reason = f"file count budget ({MAX_FILES_SCANNED}) reached"
            break
        if not ACTIVE.get() and total_bytes_read >= MAX_TOTAL_BYTES:
            result.budget_exhausted = True
            result.budget_exhausted_reason = f"total byte budget ({MAX_TOTAL_BYTES}) reached"
            break
        if not ACTIVE.get() and time.monotonic() - start_time > MAX_SCAN_SECONDS:
            result.budget_exhausted = True
            result.budget_exhausted_reason = f"time budget ({MAX_SCAN_SECONDS}s) reached"
            break

        text, skip_reason = _read_text_with_reason(file_path)
        if text is None:
            if skip_reason == "budget":
                continue
            if ACTIVE.get():
                ACTIVE.get().skipped[rel] = skip_reason or "unreadable"
            if skip_reason == "oversized":
                result.files_skipped_size += 1
            else:
                result.files_unreadable += 1
            continue
        total_bytes_read += len(text)
        result.files_scanned += 1
        file_texts[rel] = text
        # Classify the file's context once (content-aware), reused for every
        # finding in this file. (Phase 8D)
        file_ctx = classify_file(rel, content=text)
        suffix = _scan_suffix(file_path)
        syntax = _python_syntax(text) if suffix == ".py" else None
        if syntax and not syntax.parsed and ACTIVE.get():
            ACTIVE.get().parse_failures.add(rel)

        for category, name, pattern, confidence in _PATTERNS:
            if not within_budget():
                break
            for match in pattern.finditer(text):
                if not within_budget():
                    break
                classified = _classify_match_basis(suffix, syntax, text, match.start(), name)
                if classified is None:
                    continue
                evidence_basis, supports_conclusions = classified
                line_no = text.count("\n", 0, match.start()) + 1
                location_key = (rel, line_no, category, name)
                fid = location_ids.get(location_key, "")
                if not fid:
                    signal_key = (rel, category, name)
                    occurrence = signal_occurrences.get(signal_key, 0) + 1
                    signal_occurrences[signal_key] = occurrence
                    fid = _finding_id(
                        rel, line_no, category, name, stable_locator=f"occurrence:{occurrence}"
                    )
                    location_ids[location_key] = fid

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
                evidence = minimal_match_excerpt(text, match.start(), match.end())

                effective_confidence = confidence
                # Match-context guard: a dangerous-call token (eval/exec/shell) that
                # sits inside a string literal or a comment is very likely a
                # detection signature, an example, or documentation prose — not a
                # live call. Downgrade confidence rather than dropping the finding
                # (no silent drops), so a security tool's own signature strings
                # don't read as production code execution.
                if name in _SIGNATURE_PRONE_NAMES and _match_in_string_or_comment(
                    text, match.start(), line_start, comment_only=name in _COMMENT_ONLY_GUARD_NAMES
                ):
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
                        id=fid,
                        context=file_ctx.context,
                        context_confidence=file_ctx.confidence,
                        context_defaulted=file_ctx.defaulted,
                        evidence_basis=evidence_basis,
                        supports_conclusions=supports_conclusions,
                    )
                )

    # Phase 8G: resolve repo-internal imports once, for cross-file dataflow.
    result.imports_by_file = _resolve_internal_imports(file_texts) if within_budget() else {}
    if ACTIVE.get() and ACTIVE.get().reason:
        result.budget_exhausted = True
        result.budget_exhausted_reason = ACTIVE.get().reason

    return result


def _resolve_internal_imports(file_texts: dict[str, str]) -> dict[str, list[str]]:
    """Build file -> [resolved repo-internal imported files] using the AST/regex
    symbol index. Only files that actually contain AI findings matter downstream,
    but resolving for all scanned files keeps this independent of finding order.
    External packages resolve to None and are omitted."""
    from .symbol_index import build_symbol_index, resolve_js_import, resolve_python_import

    pairs = list(file_texts.items())
    index = build_symbol_index(pairs)
    out: dict[str, list[str]] = {}
    for rel, _text in pairs:
        info = index.modules.get(rel)
        if info is None:
            continue
        resolved: list[str] = []
        for target in info.imports:
            if info.language == "python":
                hit = resolve_python_import(rel, target, index)
            else:
                hit = resolve_js_import(rel, target, index)
            if hit and hit != rel:
                resolved.append(hit)
        if resolved:
            out[rel] = sorted(set(resolved))
    return out


# Pattern names most prone to string-literal / comment false positives (a security
# tool scanning FOR these tokens, or documenting an endpoint in a docstring, will
# have them as literals/comments in its source).
_SIGNATURE_PRONE_NAMES = frozenset({
    "Dynamic code execution",
    "Shell execution",
    "OpenAI-compatible HTTP endpoint",
    "Whisper transcription endpoint",
})


def _match_in_string_or_comment(text: str, match_start: int, line_start: int, *, comment_only: bool = False) -> bool:
    """Best-effort check: is the match position inside a quoted string or after a
    line-comment marker on its own line? Line-scoped and language-agnostic — not a
    real parser, deliberately conservative (only flags clear cases).

    comment_only=True restricts the check to comment/docstring context (leading //,
    #, or * ) and ignores string-literal heuristics — used for patterns like
    endpoint URLs that legitimately live inside a template literal passed to fetch()
    (a live call), where a bare backtick must NOT demote the finding."""
    prefix = text[line_start:match_start]
    stripped = prefix.lstrip()
    # comment markers: // (js), # (py/sh), or a leading * (inside a block comment)
    if "//" in prefix or "#" in prefix or stripped.startswith("*") or stripped.startswith("/*"):
        return True
    if comment_only:
        return False
    # odd number of unescaped quotes before the match => inside a string literal
    for q in ("'", '"', "`"):
        count = len(re.findall(r"(?<!\\)" + re.escape(q), prefix))
        if count % 2 == 1:
            return True
    return False


# Patterns where a string-literal is genuinely a live call argument (endpoint URLs in
# fetch template literals), so only comment/docstring context should demote them.
_COMMENT_ONLY_GUARD_NAMES = frozenset({
    "OpenAI-compatible HTTP endpoint",
    "Whisper transcription endpoint",
})
