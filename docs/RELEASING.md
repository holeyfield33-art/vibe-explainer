# Release and Compatibility Policy

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

Report schema versions are independent from package versions. Additive fields may ship
within the same major schema. Renaming/removing a field, changing serialized enum
values, or changing evidence identity semantics requires a schema-major increment and
a changelog migration note. Readers must reject unsupported schema majors rather than
silently guessing.

The report schema is `2.0` beginning with stable occurrence-based finding/control
evidence IDs and the `EVIDENCE_FOUND`/`NOT_FOUND` control vocabulary. ASI mapping has
its own schema version, also currently `2.0`.
