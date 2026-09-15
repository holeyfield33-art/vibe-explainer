# Report Handling and Retention

Vibe Explainer minimizes source excerpts and applies a shared credential redactor at
discovery, object serialization, terminal, JSON, Markdown, diagnostic, and exception
boundaries. Redaction is defense-in-depth and cannot recognize every secret or
sensitive business value. Generated artifacts remain sensitive.

For commercial assessments:

- store reports only in the approved customer workspace with least-privilege access;
- do not paste reports into public issues, chat rooms, or unapproved AI services;
- agree on a retention period before the assessment and record it in the engagement;
- remove temporary exports after delivery and securely delete retained copies when the
  agreed period ends;
- review evidence excerpts before sharing and rotate any credential suspected of
  exposure, even when the report shows `[REDACTED]`;
- treat logs and captured error output with the same controls as JSON and Markdown
  reports.

The default report includes this handling warning so downstream recipients do not
mistake redaction for declassification.
