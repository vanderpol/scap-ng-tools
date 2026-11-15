# Issue #47 Variable-function audit

This directory contains a read-only audit of two immutable candidate archives:

- `applicability.8` — SHA-256 `e164ba54ac99ed1ebc6d205205deedea311ad92abd3d83739073eb0751ae4125`
- `count.1` — SHA-256 `5e34519ee38189d8a104770fc9f1e944b7f3681edf8a76636d931026a8b02571`

The audit compares their committed `ACTIVE-CANDIDATE-RULES.json.gz` ledgers and
uses the committed `OVAL-VARIABLE-DATATYPE-INVENTORY.json.gz`. It does not
regenerate, modify, or republish either archive.

## Re-run

```bash
python scripts/audit_issue47_variable_functions.py \
  --baseline-rules /path/to/applicability.8/provenance/ACTIVE-CANDIDATE-RULES.json.gz \
  --candidate-rules /path/to/count.1/provenance/ACTIVE-CANDIDATE-RULES.json.gz \
  --inventory docs/evidence/issue28/OVAL-VARIABLE-DATATYPE-INVENTORY.json.gz \
  --out docs/evidence/issue47/function-regression
```

## Findings

- Exactly **55** Rule instances changed from `converted` to `blocked`.
- **50** regressions contain an emitted inactive generic `function` envelope;
  this is a converter admission defect, not a schema feature. The converter
  now fails closed before emitting that envelope.
- **5** regressions are unrelated datatype/possible-restriction blockers.
- **0** regressions are count-bearing. Count.1 has **32 converted** and **5
  blocked** count-bearing Rules; its five blockers are not count syntax failures.
- Active 0.4 native Variable functions are `concat`, `regex_capture`, `unique`,
  recursive `count`, and `merge`. Multi-component `unique`/`merge` and source
  `arithmetic`, `split`, `substring`, and `end` have no active 0.4 expression
  form and remain explicitly blocked.
- No runtime/scanner equivalence is claimed.

The full original blocker objects and paths are retained in
`RULE-REGRESSION-REPORT.json`; the matrix and human-readable report provide the
summary and exact Rule-level reconciliation.
