# vibe-explainer

**Make vibe-coded projects understandable — even when the original developer no longer understands them.**

Point it at a repo. Get a short mental-model report: what the project is, how the pieces fit, which files to open first, and where the opacity risk is highest.

Complements [vibe-check](https://github.com/holeyfield33-art/vibe-check):
- **vibe-check** → “What smells / how carefully should a human look?”
- **vibe-explainer** → “Here’s the map so a human can look productively.”

```bash
python -m vibe_explainer /path/to/repo
python -m vibe_explainer /path/to/repo --vibe-check-report report.json
python -m vibe_explainer /path/to/repo --offline --out EXPLAIN.md
```

## Why this exists

Vibe-coded projects often ship with:
- Little or no real documentation of *intent*
- Chaotic or AI-shaped structure
- An original author who can no longer explain the design

Existing tools do search, diagrams, or chat-with-codebase. Few are optimized for the specific failure mode: **the person who prompted this into existence has no mental model left either**.

vibe-explainer produces a *readable* artifact a stranger (or future you) can use in the first five minutes.

## What it produces (v1)

1. **Overview** — one short paragraph of what this appears to be
2. **Architecture sketch** — Mermaid (or ASCII fallback) of main components / flows
3. **Start-here guide** — ordered list of the most important files to open first, with one-line reasons
4. **Key-file summaries** — plain-English intent for the highest-value files
5. **Risk & opacity notes** — densest / least documented / most duplicated areas (grounds in a vibe-check report when provided)
6. **Suggested first questions** — natural questions a newcomer might ask the codebase

The report is deliberately short. The goal is orientation, not a generated wiki.

## Modes

| Mode | Behavior | Dependencies |
|------|----------|--------------|
| `--offline` | File tree, entry-point detection, basic structure heuristics, optional vibe-check integration | None (stdlib) |
| LLM-assisted (default when configured) | Offline pass + narrative, prioritization, and architecture synthesis | API key or local model |
| Hybrid | Deterministic structure first; LLM only for the human-readable layers | Both |

## Relationship to vibe-check

```bash
# 1. Triage
python vibe_check.py /path/to/repo --out report.json

# 2. Orient
python -m vibe_explainer /path/to/repo --vibe-check-report report.json --out EXPLAIN.md
```

When a vibe-check report is supplied, risk notes and prioritization become grounded in real findings (syntax, duplicates, dead code, package risks, etc.) instead of pure guesswork.

## Status

**Early scaffold.** Offline structural pass and report skeleton are in place. LLM layer, richer language support, and interactive HTML tour are next.

See [SPEC.md](SPEC.md) for the full product specification.

## Quick start (development)

```bash
cd vibe-explainer
python -m vibe_explainer examples/sample-vibe-project --offline
python -m vibe_explainer examples/sample-vibe-project --offline --out /tmp/explain.md
```

## Design principles (inherited from vibe-check)

- Prefer offline / deterministic where possible
- Be honest about limitations and coverage
- Produce something a human actually reads
- Stay small enough that the tool itself is understandable
- Never pretend a zero means more than what was actually checked

## Part of the Aletheia toolchain

```
Aletheia portfolio auditor  → which repos need attention
vibe-check                 → what’s wrong / triage disposition
vibe-explainer             → here’s the map so a human can look productively
Lie Detector               → does the repo do what it claims
```

## License

MIT
