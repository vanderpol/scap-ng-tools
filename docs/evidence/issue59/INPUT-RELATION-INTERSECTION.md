# Issue #59: finite integer Input constraint intersection (source-backed)

The [2026-11-13 original-source witness](https://github.com/vanderpol/scap-ng-tools/actions/runs/43541423077) locates five former conversion regressions exclusively in `assessment.inputs.*.constraints.relation` (Windows Server 2016 SV-224867 through SV-224871). The generated 0.4.1 Assessment Input contract accepts `constraints.allowed` but not `constraints.relation`; changing the source-pinned converter visitor or silently dropping the relation would be invalid.

The existing `v04_draft_inputs.external_input` source adapter obtains `allowed` from explicit OVAL external Variable `possible_value` entries, and `relation` from the linked XCCDF Value operator. The original policy Parameter and source XML remain provenance intact. For a **finite integer-only closed list** A and numeric relation P, the conjunction of both constraints is exactly represented by `allowed = [x for x in A if P(x)]` (preserves original order/duplicates). The active 0.4.1 Input schema already supports this list. This is a bounded encoding of an existing constraint, **not** an invented condition, implicit cast, new datatype, or runtime proof.

Five bounded source cases:

| Source Rule | Original allowed values | Original relation | Emitted allowed values |
| --- | --- | --- | --- |
| SV-224867 | 3, 5, 10, 50 | <= 3 | 3 |
| SV-224868 | 900, 3600, 86400 | >= 900 | 900, 3600, 86400 |
| SV-224869 | 5, 24 | >= 24 | 24 |
| SV-224870 | 5184000, 7776000 | <= 5184000 | 5184000 |
| SV-224871 | 86400, 172800, 432000 | >= 86400 | 86400, 172800, 432000 |

`native041_input_relation.project_input_relation` is atomic and fail-closed: requires a scalar integer Input, nonempty homogeneous integer allowed values, exactly one of the four reviewed source relational operators with integer bound, no unexpected keys, and a nonempty intersection. Other expressions/inputs are untouched. A source-linked receipt records the original allowed set, relation, narrowed allowed set and lack of runtime proof in conversion trace. Golden/OVAL source files are not modified.

**Qualification boundary:** Native Assessment/Input authoring validity and mathematical finite-set equivalence do not establish the evaluator's runtime handling of organizational Input policy Parameters, SCC/OVAL results, missing/error statuses or source check-export execution. Keep the PR draft and release on HOLD until full-65 per-Rule rerun and independent RI/OVAL tests pass.
