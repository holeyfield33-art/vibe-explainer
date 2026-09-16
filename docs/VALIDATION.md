# Detection-quality validation

The checked-in corpus is separate from the regression test suite. It measures whether
each labelled case is classified as authoritative evidence, an unsupported-language
lead, unresolved static evidence, or no signal.

Reproduce the published artifact offline from the repository root:

```bash
python -m vibe_explainer.validation --output validation/metrics.json --check
git diff --exit-code -- validation/metrics.json
```

`--check` enforces the issue #4 launch threshold of at least 90% Python precision. It
does not require perfect recall: missed and unresolved cases remain visible in the
artifact instead of being silently removed.

The corpus contains synthetic adversarial cases plus credential-free adaptations of
examples from pinned, permissively licensed SDK repositories. Each external case records
its repository, commit, source path, license, and adaptation note.

## Label review

The current labels were prepared alongside the implementation and are explicitly marked
`PENDING_INDEPENDENT_REVIEW`. They are useful for reproducibility and regression
detection, but they do not satisfy the independent-review gate in issue #11.

An independent reviewer should:

1. Review `validation/corpus.json` without consulting detector output.
2. Confirm or amend each expected disposition and the external-example provenance.
3. Add their name or stable reviewer identifier, review date, and reviewed commit to
   `label_review`; set its status to `INDEPENDENTLY_REVIEWED`.
4. Re-run the command above and commit any label, detector, and metric changes together.

The known obfuscated-import miss is intentionally labelled positive. Its false-negative
result is published, preserving an honest recall boundary.
