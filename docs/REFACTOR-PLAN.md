# Refactor Plan — AI Security Readiness (Phases 0–2)

## Baseline (recorded before any changes)

- Commits: 1 (`b494210 Add scanner.py and report.py core modules`)
- Modules: `scanner.py`, `report.py`, `cli.py`, `integrate_vibe_check.py`, `__init__.py`
- Total lines (vibe_explainer/): 573
- Tests: `tests/test_scanner.py` — 2 tests, both passing (`test_sample_project_scan`, `test_to_dict`)
- Example fixture: `examples/sample-vibe-project` (small Flask-shaped app, no AI signals — confirmed via grep, useful as a "no AI" control fixture going forward)

### Existing architecture

```
CLI (cli.py)
 └── scan_repo()          # scanner.py — offline file-tree walk, stdlib only
 └── load_vibe_check_report() / summarize_vibe_findings()   # integrate_vibe_check.py — optional
 └── render_markdown()    # report.py — turns ScanResult (+ vibe notes) into Markdown
```

### Existing CLI behavior

`vibe-explainer <repo> [--offline] [--vibe-check-report PATH] [--out PATH] [--format markdown]`

Note: `--offline` is currently a no-op — `cli.py` hardcodes `offline = True if args.offline or True else True`,
so every run is offline regardless of the flag (there is no LLM layer implemented yet). This refactor
does not touch that; flagged here so it isn't mistaken for new behavior.

### Existing report behavior

Markdown sections: Overview, Architecture sketch (Mermaid), Start here, Key files, Risk & opacity notes
(vibe-check-grounded if a report was supplied, else a structural giant-file heuristic), Suggested first
questions. All derived from `ScanResult` — no AI-awareness of any kind today.

### Existing scanner behavior

`scan_repo()` walks the tree (skipping `.git`, `node_modules`, `__pycache__`, etc.), detects entry points
and manifests by filename, counts lines/size per code file, and buckets by extension and top-level directory.
Returns a `ScanResult` dataclass with `to_dict()`. No content-level inspection — filenames and line counts only.

### Existing tests

`tests/test_scanner.py` scans `examples/sample-vibe-project` and asserts entry points, manifests, and
line counts are found. No content-inspection tests exist yet (nothing to test — scanner doesn't read content).

## Proposed new modules (Phases 1–2 of this pass)

- `vibe_explainer/ai_discovery.py` — content-level AI component discovery (model providers, AI usage,
  prompt surfaces, RAG/retrieval, tools/agents, MCP, external integrations, secrets/config). Each finding
  carries `type`, `name`, `file`, `line`, `evidence`, `confidence`.
- `vibe_explainer/attack_surface.py` — groups `AIFinding`s from `ai_discovery` into the six-bucket AI
  attack-surface model (Inputs / Model / Retrieval / Tools / Outputs / Storage) with security relevance
  notes. Pure static-discovery grouping — does not attempt to prove exploitability.

Later phases (3–11: data-flow, controls, risk scoring, readiness classification, reporting, JSON schema,
CLI wiring, full fixture matrix, docs) are explicitly **out of scope for this pass** and deferred to a
follow-up refactor once Phases 1–2 have been reviewed.

## Compatibility strategy

- No changes to `scanner.py`, `report.py`, or `cli.py` in this pass. Existing CLI behavior, existing tests,
  and the existing mental-model report are untouched and continue to work exactly as before.
- `ai_discovery.py` and `attack_surface.py` are additive, importable modules with their own test files.
  They are not yet wired into the CLI or the Markdown report — that's Phase 7/9 territory per the original
  directive, deferred until the discovery output itself has been reviewed.
- Reuses `scanner.SKIP_DIRS` for directory pruning (DRY — one skip-list, not two).

## Explicit non-goals (this pass)

- No data-flow tracing (Phase 3)
- No security-control checks (Phase 4)
- No risk scoring or readiness classification (Phases 5–6)
- No report/CLI/JSON-schema wiring (Phases 7–9)
- No SaaS, auth, billing, hosted API, runtime enforcement, or exploit generation (directive non-goals,
  unchanged)
