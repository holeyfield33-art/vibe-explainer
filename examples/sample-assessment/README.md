# Sample assessment

`synthetic-ai-review.md` is generated from the synthetic fixture in
`examples/analyst-review-fixture` using the current default evidence-review behavior:

```bash
python -m vibe_explainer examples/analyst-review-fixture --report -o examples/sample-assessment/synthetic-ai-review.md
```

The fixture is invented and contains no customer information or real credentials. The
report demonstrates analyst-reviewable evidence, completeness, provenance, and explicit
limitations. It is not a penetration test and does not prove exploitability, runtime
behavior, or control effectiveness. Default output contains no numeric vulnerability
score, severity award, or awarded readiness/maturity level.
