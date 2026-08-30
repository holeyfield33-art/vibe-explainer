# Phase 6 — AI Security Readiness Assessment

> **Gameability warning:** Levels are inferred from repository paths, headers, code
> keywords, and CI text. The scanner does not prove that tests are substantive, CI is
> enforced, or documented processes operate in practice.

**Readiness measures demonstrated AI security maturity and repeatability. It is
independent of the severity of individual risk scenarios.**

**Running Vibe Explainer does not itself increase the assessed readiness of the target
repository.**

## 1. Purpose

Answer: *"How mature and repeatable is the repository's demonstrated AI security
practice?"* — never *"what is the highest current security risk?"*
`assess_readiness(discovery, attack_surface, dataflow, controls, risks) -> ReadinessAssessment`
consumes all five prior phases and performs exactly one new thing: a small, isolated
scan for repository **process** evidence (test directories, CI config, documentation) —
never a second AI-component scan.

## 2. Risk vs readiness

A risk score (Phase 5) answers "how concerning is this identified evidence scenario."
Readiness answers "how mature and repeatable is the security testing program." These
are independent axes, verified directly: `agent-with-tools` (one HIGH-severity risk
scenario, zero process evidence) and `basic-chatbot` (only LOW-severity risk, zero
process evidence) land at the **same** readiness level — Level 1 — because neither has
any process evidence, regardless of how their risk profiles differ. Conversely,
`controls-well-controlled` (four `DETECTED` Phase 4 controls, zero risk scenarios
generated) still caps at Level 1, because control density and risk absence aren't
process evidence either.

## 3. Four readiness levels

| Level | Name | Core question |
|---|---|---|
| 1 | Baseline | Has AI been brought into security scope at all? |
| 2 | Managed | Is there a repeatable, documented AI security testing practice? |
| 3 | Hardened | Does that testing integrate into CI/release workflow? |
| 4 | Continuous | Is there an ongoing, scheduled assurance loop with versioned evidence? |

## 4. Level gates (mandatory, non-negotiable per level)

| Level | Gate | Cannot be satisfied by |
|---|---|---|
| 1 | Any AI component discovered (Phases 1–3 evidence) | — always achievable once AI exists |
| 2 | A security/redteam/eval test-path convention (`tests/security/`, `tests/redteam/`, `evals/`) **or** a documented AI evaluation process in repo docs | Vibe Explainer's own generated attack-surface report; the target repo's ordinary unit tests |
| 3 | Level 2 ≥ PARTIAL **and** a CI config file that references both a security/eval keyword and a test-run step | CI existing with no security-relevant content |
| 4 | Level 3 ≥ PARTIAL **and** that same CI security gate **and** a scheduled/cron trigger in the CI config | CI + tests alone (no schedule); logging alone |

Each level's status is `ACHIEVED` only when the gate is met **and** at least a
threshold of supporting evidence exists (2 of 3 signals for Level 2/3, 3 of 3 for
Level 4 — deliberately stricter at the top, since the directive requires the full
change→eval→decision→evidence→monitoring loop, not one artifact). Gate met but
supporting evidence thin → `PARTIAL`. Gate not met → `NOT_ACHIEVED`, with the specific
missing requirement named.

**Final level = the highest level with status `ACHIEVED`.** A `PARTIAL` at a level
does not count toward the final level, matching the directive's own worked example
(L1 ACHIEVED, L2 PARTIAL, L3/L4 NOT_ACHIEVED → final = Level 1).

## 5. Evidence types

- `DISCOVERY_EVIDENCE` — from Phase 1 (AI components found)
- `DATAFLOW_EVIDENCE` — from Phase 3 (relationships observed)
- `CONTROL_EVIDENCE` — from Phase 4 (control status)
- `RISK_EVIDENCE` — from Phase 5 (referenced as context only, never as level evidence)
- `PROCESS_EVIDENCE` — from this phase's own scan (test paths, CI config, doc headers)
- `REPOSITORY_ARTIFACT` — reserved for future direct-artifact evidence types

## 6. Process evidence (this phase's one new scan)

Isolated in `_scan_process_signals()` — a single walk of the target repository
checking:

- **Path conventions**: `tests/security/`, `tests/redteam/`, `evals/` (high
  confidence); filenames containing `security_test`/`redteam_test`/`adversarial_test`
  (moderate).
- **CI config presence**: `.github/workflows/*.yml`, `.gitlab-ci.yml`,
  `.circleci/config.yml`.
- **CI security gate**: a CI file containing both a security/eval keyword
  (`security|adversarial|redteam|eval`) and a test-run step (`run:`/`pytest`/etc.).
- **Scheduled evaluation**: that same CI file also containing `schedule:` and `cron:`.
- **Documentation headers**: `## AI Security Evaluation Process`,
  `## Remediation Workflow`, `## Security Metrics`, `## Risk Register` (same
  header-matching approach as Phase 4's C01/C02, applied to a different vocabulary).
- **Versioned evidence**: a `security-reports/` path or a filename containing a
  `YYYY-MM-DD` date.

This is deliberately narrow — a real second scanning system was explicitly a
non-goal.

## 7. Process evidence vs generated assessment evidence

Mandatory distinction, enforced in code: Phase 1–5's own output (discovery findings,
attack-surface buckets, data-flow edges, control results, risk scenarios) is
`DISCOVERY_EVIDENCE`/`DATAFLOW_EVIDENCE`/`CONTROL_EVIDENCE`/`RISK_EVIDENCE` — it
proves *what Vibe Explainer found*, and only ever satisfies Level 1's "AI brought into
scope" requirement. It is never counted toward Level 2/3/4's process gates. Only
`PROCESS_EVIDENCE` from the target repository's own test paths, CI config, and
documentation can satisfy those. Verified directly:
`test_running_vibe_explainer_on_itself_is_not_special_cased` and the false-positive
suite (`test_ordinary_project_tests_do_not_establish_level_two`, using this very
project's own `tests/` directory as the negative case, since it isn't at
`tests/security/`).

## 8. Confidence

Confidence in the readiness judgment itself. `high` for Level 1 (discovery evidence is
always directly observed) and for any level whose gate is met with full supporting
evidence; `moderate` for `PARTIAL` levels and for `NOT_ACHIEVED` levels (absence
judgments carry the same "not proven absent everywhere" caveat as Phase 4's
`NOT_DETECTED`).

## 9. Completeness

`assessment_completeness` propagates from Phase 1's truncation flag (via Phase 5,
which already carries it) — `PARTIAL` whenever `DiscoveryResult.truncated` is
non-empty. Verified against the `truncation-heavy` fixture.

## 10. Level selection

Walk Levels 1→4; a level only counts as the final answer if its own status is
`ACHIEVED` (not `PARTIAL`) — see §4. `blockers` on the final `ReadinessAssessment`
lists the specific missing requirements for the next level up, so a report layer can
say "here's what would move you to Level N+1" without re-deriving it.

## 11. Examples

- **No-AI repository**: `readiness_level=None`, `readiness_name="NO_AI_SURFACE"` — not
  Level 1 `NOT_ACHIEVED`, a distinct state, since there's no AI security question to
  answer at all.
- **Baseline**: `basic-chatbot` — AI discovered, zero process evidence → Level 1,
  with gaps (`documented AI inventory`, `documented threat model`,
  `formal risk register`) explicitly listed even though the level is `ACHIEVED`.
- **Managed**: `readiness-managed` fixture — a `tests/security/` directory, a
  documented evaluation process, and a `DETECTED` tool-authorization control together
  clear the Level 2 gate and its 2-of-3 supporting threshold.
- **Hardened**: `readiness-hardened` — adds a CI file that runs the security tests on
  pull request (no schedule) plus a remediation-workflow doc and audit logging →
  Level 3.
- **Continuous**: `readiness-continuous` — adds a `schedule:`/`cron:` trigger to that
  same CI file, plus a security-metrics doc and a dated `security-reports/` artifact →
  Level 4.

## 12. Limitations

- Process evidence is detected via path conventions, CI keyword matching, and doc
  headers — not by verifying the process actually executes, passes, or is enforced. A
  CI file that references security tests but never actually runs them (or always
  passes trivially) looks identical to a real one from this scanner's vantage point.
- Entirely invisible to processes that live outside the repository — a red-team
  engagement tracked in an external ticketing system, a vendor pentest report kept
  elsewhere, a security review conducted in a private channel.
- The Level 2–4 supporting-evidence thresholds (2-of-3, 2-of-3, 3-of-3) are a
  deliberately simple, documented cutoff, not a calibrated statistical model — two
  repositories with slightly different evidence mixes can land on different sides of
  an `ACHIEVED`/`PARTIAL` boundary.
- Inherits Phase 4's regex/keyword-only limitation for anything that reuses control
  evidence (governance signals feeding Level 2).
- No cross-file or cross-repository resolution — a CI config in a separate
  infrastructure repo that actually gates this repository's releases is invisible
  here, same limitation Phase 3 already documents for code.
