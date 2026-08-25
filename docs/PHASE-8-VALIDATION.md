# Phase 8 Validation Log

Real-repository validation runs. Each real repo has surfaced a distinct bug/gap class
that fixture-only testing would not have. This log records what was run, what was
found, and what changed — the honest record the directive (8N) asks for.

## Repo 1 — runtime-firewall-mvp (Aletheia Firewall)

**What it is:** A Node.js *runtime security firewall* (intercepts `require()`/ESM to
detect malicious packages). Monorepo, 278 files, heavy `test/`, `esm-fixtures/`, and
`red-team/corpus/` content. **Essentially no production AI surface** — no LLM SDKs, no
model calls; the "AI-looking" tokens are detection signatures and adversarial samples.

**Baseline (pre-Phase-8):** 56 AI findings, "AI SURFACE DETECTED." Almost all false
positives.

**Gap classes found:**
1. *Language-mismatched pattern (real bug).* The dynamic-code-execution pattern
   `\b(?:eval|exec)\(` fired on JS `re.exec(str)`, `.exec(content)`, `child.exec()` —
   regex matches and method calls, not code execution. **Fixed:** tightened to
   `(?<![.\w])(?:eval|exec)\(`. Regression test added.
2. *Detection-signature strings/comments (context, not detection).* A security tool's
   source legitimately contains `'eval('` as a scanned-for literal and in comments.
   **Fixed:** a match-context guard downgrades a dangerous-call token inside a string
   literal or comment to `low` confidence — downgraded, never dropped (no silent loss).

**After:** 56 → 40 findings; 30 of 40 correctly demoted to `low` confidence. 278 files
crawled, 254 analyzed, 0 silent drops.

**Verdict:** For a no-AI security tool, the honest answer is "low/uncertain AI surface."
The fixes moved it decisively toward that. The residual signature-array literals
(`['eval(', 'exec(']`) are handled by SECURITY_TEST/detection context weighting
downstream rather than more regex surgery.

## Repo 2 — creator-ai-hub-v2 (Creator AI Hub)

**What it is:** A real **AI content application** — transcribes/summarizes a source and
generates channel-specific social posts via an LLM. TypeScript/Next.js full-stack
(51 `.ts`, 14 `.tsx`), 174 files. Carries a Lie Detector badge. This is a genuine
production AI app.

**Baseline (pre-Phase-8, post TS-fix-1):** only 6 findings, 0 risk scenarios. A large
**false-negative** — the engine was nearly blind to the app's real AI core.

**Gap class found:** *TS/JS AI idioms uncovered (detection coverage).* The app calls
OpenAI via **raw `fetch()` to `https://api.openai.com/v1/chat/completions`** with a
`Bearer ${apiKey}` header and a `{ model, messages: [{ role, content }] }` body — plus
Whisper transcription — none of which the Python/SDK-oriented patterns matched.

**Fix (legitimate detection addition — the opposite call from repo 1):** added precise
TS/JS patterns:
- OpenAI-compatible HTTP endpoint (`api.openai.com/v1`, `/chat/completions`) — high
- Whisper transcription endpoint (`whisper-1`, `/audio/transcriptions`) — high
- Vercel AI SDK (`generateText`/`streamText`/`@ai-sdk/`) — high
- Chat messages array (`messages: [{ role: …`) — moderate
- Chat role message (`role: 'system'|'user'|'assistant'`) — moderate
- Broadened model-key env vars to include `AI_API_KEY` / `AI_MODEL` / `AI_BASE_URL`

**After:** 6 → 25 findings (15 production-context), 2 risk scenarios. The OpenAI HTTP
call, Whisper endpoint, prompt surface, and API-key handling are now all detected.

**Cross-check (critical):** the same new patterns produced **0 new findings** on
runtime-firewall-mvp (the no-AI repo) — the additions are precise, not broad. A
dedicated over-fire test confirms a plain non-AI TS file with a `messages` variable and
a local `fetch` is not flagged.

**Note (not changed):** creator-ai-hub reports `PARTIAL` because `ai-provider.ts`
genuinely exceeds `MAX_FINDINGS_PER_FILE_PATTERN` (3) for OpenAI references. The flag is
*honest*, but the aggressive cap makes most real AI apps read as "INCOMPLETE." Whether
to raise the cap is a cross-repo tuning decision deferred rather than made mid-run.

## Cross-repo principle confirmed

The two repos required **opposite** responses, and getting that call right is the whole
point of context-aware analysis:
- The **no-AI security tool** needed *less* detection / more context (downgrade
  signatures) — adding regexes there would have made it worse.
- The **real AI app** needed *more* detection (TS idioms) — context weighting alone
  would never have surfaced a call the patterns couldn't see.

A single "add more patterns" or "add more filtering" reflex would have damaged one repo
to help the other. The fix in each case was matched to what the repo actually is.

## Still pending

- 2 more validation repos (directive asks for ~4 total).
- Downstream Phase 8 integration (file_context onto findings, AST cross-file edges into
  the dataflow graph, context-aware risk weighting, readiness SECURITY_TEST credit,
  report production/test separation).
- `MAX_FINDINGS_PER_FILE_PATTERN` tuning decision.

## Repo 3 — aegis-provenance (Aegis Provenance Proxy)

**What it is:** An **LLM-security middleware** — a provenance-enforcing context proxy
that wraps LLM interactions, marks untrusted content inert, and gates tool calls before
egress. Pure TypeScript, 88 files. The hardest case so far: it is *about* AI security,
so its production code legitimately contains injection strings, tool-gating logic, and
an OpenAI-compatible client (for its own eval mode). Neither "no AI" (repo 1) nor
"straightforward AI app" (repo 2).

**Baseline (post repo-1/2 fixes):** 35 findings, 29 "production." Mostly the tool's own
domain vocabulary, not app AI usage.

**Gap classes found:**
1. *Bare-word `webhook` pattern — pure noise.* Across all three repos it produced 16
   findings, **0 real** — matching fixture names, an exfiltration-detection regex, and
   corpus descriptions. **Fixed:** replaced the bare noun with a webhook-*handler*
   idiom (`@app.route('…/webhook…')`, `handle_webhook`, `register_webhook`, etc.).
   Result: 16 → 0 noise findings across the three repos, no real finding lost.
2. *Endpoint URL in comment vs. live call.* The comment guard (added in repo 1) didn't
   cover the new endpoint-URL patterns, so a docstring mentioning `/chat/completions`
   read as `high`. Extended the guard to endpoint patterns — but with a `comment_only`
   refinement, because an endpoint URL inside a **template literal passed to fetch()**
   is a live call, not a doc reference, and a naive backtick check wrongly demoted it.
   Now: URL in `//`/`*` comment → `low`; URL in `fetch(\`…/chat/completions\`)` → `high`.

**After:** 35 → 22 findings. The 8 high-signal production findings now point precisely
at the one real model-calling module (`src/clients/openai-compat.ts`, the actual
`fetchImpl(\`${baseUrl}/chat/completions\`)` call is `high`) and the eval harness —
exactly the real AI surface, with comments/imports/fixtures correctly demoted to `low`.

**Verdict:** For an LLM-security middleware, the honest picture is "one real model
client plus an eval harness, embedded in a lot of security-domain vocabulary." The
engine now produces that instead of 35 smeared findings.

## Running tally

| Repo | Type | Findings before→after | Bug/gap class |
|------|------|----------------------|---------------|
| runtime-firewall-mvp | No-AI security tool (JS) | 56 → 40 | JS `.exec()` FP; signature-string context |
| creator-ai-hub-v2 | Real AI app (TS) | 6 → 25 | TS raw-fetch AI idioms (false-negative) |
| aegis-provenance | LLM-security middleware (TS) | 35 → 22 | bare-word webhook noise; comment-vs-live-call |

Three repos, three distinct fix classes, each matched to what the repo actually is. No
repo's fix damaged another's result — re-verified after each change.

## Repos 4-6 — post-Phase-8 validation

Run with the completed Phase 8 engine (context layer + cross-file resolution active).

### Repo 4 — aletheia-core (THE original benchmark)

This is the repository whose first-run report + red-team review *motivated* Phase 8.
Re-running the finished engine against it is the real test of whether the flagged gaps
closed. 459 files (Python + TS), 418 analyzed, 0 silent drops, ~4s.

The original review's central complaint was noise: production code, tests, security
tests, docs, examples, and demo payloads were indistinguishable. The finished engine
now reports them separately: **38 production, 35 test, 18 security-test, 6 demo, 5
config, 2 fixture.**

Every specific item the review called out is now correct:
- **Production RAG/embeddings the review manually verified as real** — Qdrant in
  `core/vector_store.py` and the embeddings call at `core/model_loader.py:51` (the exact
  line the review cited) — surface as `high`-confidence PRODUCTION findings.
- **The `LiveAletheiaDemoSection` injection payload** the review flagged as a *false*
  production prompt-injection surface — all 6 demo-file findings now classify as `DEMO`,
  and there are **0 production `prompt_surface` findings**. The payload is seen but
  context-demoted, exactly the `Finding → Context → Production/Test/Example` flow the
  review proposed.
- **Bare-word webhook noise** ("webhook references all over" but only `WebhookExporter`
  is real) — 0 spurious webhook findings after the handler-idiom fix.
- Assessment correctly `PARTIAL` (large repo, real truncation), readiness L1.

Verdict: the repo that motivated Phase 8 now reads the way the reviewer said it should.

### Repo 5 — project-eclipse (marketing says AI, code has none)

18 Python + 9 TSX files. The README markets it as an "AI-powered threat intelligence
platform," but a full scan finds **zero** AI/LLM signals in the actual code — it's a
FastAPI + React scaffold with no model integration yet. The engine reports
`NO_AI_SURFACE` — the honest verdict from code evidence, not the marketing claim. It was
not fooled by "AI-powered" in the README into fabricating a surface. (Correct zero,
unlike creator-hub's earlier false-negative where the AI was real but idiom-hidden.)

### Repo 6 — aletheia-portfolio-auditor (small, real cross-file structure)

26 files, dense Python. 24 findings (18 production), 1 LOW risk, **15 dataflow edges of
which 4 are cross-file**. The cross-file edges are legitimate: `cli.py` (API-key config)
imports `providers.py` (model provider + AI usage), yielding a real
`secret_config → model_provider` cross-file edge — a credential-in-one-module flowing to
model-use-in-another, exactly what same-file-only analysis missed. Assessment `PARTIAL`,
readiness L1.

## Full tally (6 repos)

| Repo | Type | Result |
|------|------|--------|
| runtime-firewall-mvp | no-AI security tool (JS) | 56→40→37; JS exec FP + signature context |
| creator-ai-hub-v2 | real AI app (TS) | 6→25; recovered TS raw-fetch idioms |
| aegis-provenance | LLM-security middleware (TS) | 35→22; webhook noise + comment guard |
| aletheia-core | large mixed AI platform | noise separated: 38 prod / 35 test / 18 sec-test / 6 demo; every review item closed |
| project-eclipse | no-AI (despite marketing) | NO_AI_SURFACE — honest zero |
| aletheia-portfolio-auditor | small AI tool | 4 legitimate cross-file edges (secret→model) |

Six repos across five distinct repo types. The two hardest cases — the benchmark that
motivated the phase, and a repo whose README overclaims AI — both now read honestly.
