# Validation corpus labeling policy

Corpus labels are ground truth proposed independently of current detector output.

- `authoritative`: supported structural/static evidence exists and may be used in
  downstream evidence conclusions. It does not confirm a vulnerability, runtime
  behavior, or exploitability.
- `unresolved`: relevant evidence exists, but the supported static analyzer cannot
  establish enough structure to classify it authoritatively.
- `unsupported`: relevant lexical evidence exists in a language or construct outside
  the authoritative analysis boundary. Python comments are intentionally retained as
  non-authoritative research leads under this label; comment-only evidence can never
  support a conclusion.
- `none`: no relevant evidence should be produced.

Positive cases identify the expected finding category, detector name, and evidence
basis. Context and structural relationships are separate labeled axes. A case does not
pass merely because an unrelated authoritative finding exists.

`mandatory: false` is reserved for a published known limitation whose mismatch is
allowed by the current release policy. It remains a false negative in precision/recall
and is printed by every validation run. It is never relabeled to improve metrics.

## Independent review

```text
implementation team proposes labels
        ↓
independent reviewer checks labels without using detector output as ground truth
        ↓
disputes are recorded
        ↓
labels are corrected if needed and the corpus version is incremented
        ↓
review status is changed for that exact corpus version
```

The reviewer must record a stable identity, reviewed version, date/commit in review
notes, and any disputes. Implementation authors cannot self-approve the labels.
