# Release and Compatibility Policy

## Analyst-assisted beta qualification (2026-09-17)

Run builds serially: setuptools uses shared checkout build directories. Install
developer tooling in a dedicated environment; the engine has no runtime dependencies.
These PowerShell commands reproduce the complete qualification on Windows:

```powershell
git clone https://github.com/holeyfield33-art/vibe-explainer.git
cd vibe-explainer
git checkout <reviewed-candidate-commit>
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements-qualification.txt
git clone --depth 1 https://github.com/openai/openai-python.git "$env:TEMP/vibe-beta-targets/openai-python"
git clone --depth 1 https://github.com/langchain-ai/langgraph.git "$env:TEMP/vibe-beta-targets/langgraph"
git clone --depth 1 https://github.com/BerriAI/litellm.git "$env:TEMP/vibe-beta-targets/litellm"
.venv/Scripts/python scripts/qualify_clean_environment.py --revision HEAD --large-targets "$env:TEMP/vibe-beta-targets" --output dist/beta-qualification
```

For exact upstream inputs, checkout the SHAs in LARGE-REPO-QUALIFICATION.md
(fetch those commits if a shallow clone does not contain them). Upstream changes
must not be judged by finding-count equality. Use the same Python version and
platform when comparing operational timing. On POSIX use `.venv/bin/python` and
explicit temporary-directory paths.

The clean harness clones the **committed** revision locally into a fresh directory,
creates a new virtualenv, installs only pinned developer tools, then runs the
complete release script. It preserves logs, exact source SHA, exit codes and large
repository artifacts in the output directory. Dirty/uncommitted edits are excluded.
Tool acquisition may require network access; scan, rendering and release checks
are offline. Targets are never installed, imported or executed.

Individual commands from the configured environment:

```powershell
python -m pytest -q
python -m coverage run -m pytest -q
python -m coverage report --fail-under=90
python scripts/check_product_boundary.py
python -m vibe_explainer.validation --output dist/metrics.json --metrics-gate --check
python scripts/review_detection.py
python scripts/golden_report.py
python -m build --no-isolation --outdir dist
python scripts/qualify_large_repos.py --targets "$env:TEMP/vibe-beta-targets" --output dist/large-repos --max-seconds 2
python scripts/qualify_release.py --large-targets "$env:TEMP/vibe-beta-targets" --large-output dist/large-repos
```

The release script builds wheel **from the sdist**, checks package contents, installs
the wheel without dependencies/index in another fresh venv, checks isolated import
location, invokes installed help/version and generates JSON/Markdown outside the source
directory. This distinguishes installed-package behavior from imports from a checkout.

Interpret failures precisely: tooling/venv/pip acquisition is a developer-environment
failure; build/archive/install errors are packaging failures; pytest/coverage failures
are test failures; corpus mismatch is validation failure; independent label review,
analyst signoff and missing external qualification inputs are release blockers.
An exit 1 due solely to pending signoff does not mean package installation failed.
No GO is possible with mandatory gates pending, even when all automated tests pass.

The next proposed version, **only after GO**, is `0.2.0b1`. Do not change the version
or issue a tag while this review is NO-GO. After approval, change the sole version
source and hardcoded qualification/test expectations deliberately, regenerate/review
the golden artifact, rerun clean qualification on that commit and verify CI.
Proposed subsequent commands (not executed):

```powershell
git add <reviewed-release-files>
git commit -m "Prepare 0.2.0b1 analyst-assisted beta"
python scripts/qualify_clean_environment.py --revision HEAD --large-targets "$env:TEMP/vibe-beta-targets" --output dist/beta-qualification
git tag -a v0.2.0b1 -m "Vibe Explainer 0.2.0b1 - Analyst-Assisted Beta"
# Only with separate authorization:
git push origin main
git push origin v0.2.0b1
```

## Scan budget contract

`--max-files`, `--max-bytes`, `--max-seconds` apply to the default evidence-review
pipeline, across discovery, relationships, controls and process-artifact reads.
Defaults: 20,000 unique files, 200,000,000 unique raw bytes, 120 seconds. Positive
finite values are required. Legacy orientation mode retains its previous behavior.
The existing human-readable `budget_exhausted_reason` vocabulary is preserved.
There is no separate configurable parse budget; parse failures are listed and reduce
CLI completeness to PARTIAL. Per-file reads remain capped at 500,000 bytes.

Exit 0 means an artifact was generated successfully, including expected budget-driven
PARTIAL reports; exit 1 means analysis/output failure; exit 2 means invalid invocation
or an existing output without `--force`. Temporary sibling files, fsync and atomic
publication prevent truncated replacements. Automation must inspect completeness.

Time limits are cooperative checkpoints, not hard real-time deadlines: a bounded
read, regex or AST operation may finish after the deadline; assembly, redaction,
Git provenance and atomic output take additional time. Sorted traversal is
deterministic; elapsed-time cutoffs and timings necessarily vary by machine/load.
File/byte limits provide reproducible scope. The qualification watchdog is only a
failure detector; watchdog termination never passes graceful-completion qualification.

`scan_scope` counts files discovered in visited directories, files whose content was
read, skipped discovered files, unique bytes, parse failures, exclusions and unsupported
AI-discovery extensions. Counts are lower bounds when traversal ends early; content
read does not imply every downstream analysis completed. No full extra inventory walk
is performed after exhaustion. No numeric confidence/maturity score is inferred from
coverage. Uninspected scope cannot support absence claims. Keep target trees immutable
during scans: the reader is not a race-proof operating-system sandbox.

JSON omits generation timestamps; operational elapsed seconds are metadata. Golden
tests normalize operational fields only, preserving evidence and conclusions.

## Historical release policy

Vibe Explainer uses semantic versioning. The sole package-version source is
`vibe_explainer.__version__`; `pyproject.toml`, the installed console command, and
report metadata read that value dynamically.

Before a release:

1. Move relevant `CHANGELOG.md` entries from **Unreleased** to a dated version.
2. Update `vibe_explainer.__version__` once.
3. Run the complete test suite and branch-coverage gate on Python 3.11–3.14.
4. Build sdist and wheel, install the wheel in a clean environment, run
   `vibe-explainer --version`, and uninstall it.
5. Require green Python and CodeQL workflows on the exact release commit.

The historical `v0.1.0` tag represents the initial scored/readiness-oriented behavior
and must not be moved or rewritten. The `0.2.x` line establishes the narrowed,
analyst-reviewed evidence boundary: default scoring and readiness awards are removed,
control semantics and Python discovery are structural, relationships require bounded
AST evidence, report schema 2.0 is in use, and ASI mapping has independent evidence axes.

Run the complete local qualification with:

```bash
python scripts/qualify_release.py
```

The local command does not replace green CI, CodeQL, branch protection, independent
corpus-label review, or manual analyst review of the golden report.

Report schema versions are independent from package versions. Additive fields may ship
within the same major schema. Renaming/removing a field, changing serialized enum
values, or changing evidence identity semantics requires a schema-major increment and
a changelog migration note. Readers must reject unsupported schema majors rather than
silently guessing.

The report schema is `2.0` beginning with stable occurrence-based finding/control
evidence IDs and the `EVIDENCE_FOUND`/`NOT_FOUND` control vocabulary. ASI mapping has
its own schema version, also currently `2.0`.
