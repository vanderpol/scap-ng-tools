# Issue #28 OVAL-to-SCAP-NG coverage matrix

The machine-readable [matrix](OVAL-COVERAGE-MATRIX.json) separates schema,
compiler, converter, runtime, and proof status. A schema-valid document is not
an equivalence or scanner claim. The 65-benchmark baseline remains 8,892 Rules.

## Status counts in the reviewed matrix

| Classification | Meaning |
|---|---|
| Fully supported and proved | Source-backed implementation plus independent semantic vectors |
| Supported but converter mapping missing | Native direction exists or is approved, but conversion is still blocked |
| Partially implemented | A bounded mapping exists; runtime or source-equivalence proof remains open |
| Missing from native language | No faithful current 0.4 capability contract |
| Intentionally excluded | Owner decision excludes the source feature; source/provenance is retained |

`all_exist` is intentionally marked partial: the owner-approved native spelling
maps it to `one_or_more`, but the independent empty/error vectors do not by
themselves prove equivalence to an OVAL engine. Access-token and legacy `wmi_*` capabilities are tracked together as
**Deprecated OVAL Tests**; no equivalents are fabricated. `wmi57_*` is tracked
as supported WMI. SQLEXT-dependent SQL benchmarks are excluded rather than converted.

## Proof boundary

The independent vectors in `tests/test_issue28_semantic_proof.py` are an oracle
for lexical functions, cardinality, empty values, and diagnostic propagation.
They do not execute generated Assessments or establish scanner equivalence.
