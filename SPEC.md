# Vibe Explainer — Product Spec (v0.1)

## Problem

People act like they cannot adopt vibe-coded projects. Often the original developer cannot explain the code either. The cost of understanding feels higher than the value of the project.

## Solution

A tool that produces a short, honest **mental-model report** so a new person (or future self) can orient quickly and start changing the code with confidence.

## Goals

- Orientation in < 5 minutes for a typical small/medium vibe-coded repo
- Useful even when no human can explain the original intent
- Complementary to deterministic scanners (especially vibe-check)
- Local-first options; honest about what is LLM vs deterministic
- Report length stays human-scale (target: readable in one sitting)

## Non-goals (v1)

- Full automated refactoring or “clean up my entire codebase”
- Behavioral proof / execution of claims (see Lie Detector)
- Perfect multi-language parity on day one
- Replacing human judgment or code review

## Primary user stories

1. **Adopter**: “I found this repo / was handed this project. I need to know where to start reading and what the main pieces are.”
2. **Original author**: “I vibe-coded this three weeks ago and no longer remember how it works. Help me regain a map.”
3. **Reviewer / auditor**: “I need a fast high-level picture plus the places most likely to be opaque or risky before I dive in.”

## Inputs

- Path to a local repository (required)
- Optional: path to a vibe-check JSON report
- Optional (future): agent session logs / chat history
- CLI flags: `--offline`, `--format`, `--out`, depth / language hints

## Outputs

Markdown report (primary) containing:

1. Overview (1 short paragraph)
2. Architecture sketch (Mermaid preferred, ASCII fallback)
3. Start-here reading order (5–8 items with reasons)
4. Key-file / module summaries (highest-value only)
5. Risk & opacity notes (optionally grounded in vibe-check findings)
6. Suggested first questions a newcomer might ask

Future: self-contained HTML interactive tour, JSON machine-readable export.

## Architecture (tool itself)

```
CLI
 ├── scanner        # file tree, entry points, language detection, basic structure
 ├── integrate      # optional vibe-check report loader
 ├── synthesizer    # offline heuristics + optional LLM layer
 └── report         # markdown / mermaid / (future HTML) renderer
```

### Offline / deterministic layer

- Walk the tree (respecting common ignore patterns)
- Detect likely entry points (main, app, index, server, cli, routes, etc.)
- Detect package manifests and high-level stack signals
- Rank files by size, centrality heuristics, and name signals
- Surface directory shape and obvious layers (frontend/backend, routes/services/models, etc.)

### LLM layer (optional)

- Turn structural facts into a coherent narrative overview
- Propose a sensible architecture diagram
- Write the “why this file first” reasons and key-file summaries
- Generate natural first questions
- Stay constrained: short, concrete, grounded in the files that were actually seen

## Success metrics (qualitative for v1)

- A stranger can open the report and know the first three files to read within two minutes
- Original author reaction: “yes, that matches what I was trying to build”
- Report does not balloon into an unreadable generated wiki
- Offline mode still produces something useful when no API key is present

## Relationship to the Aletheia / vibe toolchain

```
Aletheia portfolio auditor  → which repos need attention
vibe-check                 → what’s wrong / triage disposition
vibe-explainer             → here’s the map so a human can look productively
Lie Detector               → does the repo do what it claims
```

## Open questions / later

- How aggressively to support session-log / prompt archaeology
- Whether to emit characterization-test stubs
- Interactive HTML vs pure markdown first
- Local model support (Ollama etc.) as first-class offline+LLM path
