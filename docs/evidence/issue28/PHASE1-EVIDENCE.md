# Issue 57 Phase 1 evidence

Source: pinned `OVAL-Community/SCAP-Self-Assertion` commit
`e3538595c5083b9c34d937a81d319234df9bbfaa`.  Phase 1 does not add 0.4
semantics or runtime equivalence claims.

## OVAL Test Content

| ledger | Definitions | converted | blocked | authorized AIX excluded | Tests | converted | blocked | authorized AIX excluded |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| before Cycle 1 | 168 | 90 | 78 | 0 | 803 | 434 | 369 | 0 |
| after Cycle 1 + Phase 1 ledger repair | 168 | 97 | 69 | 2 | 803 | 523 | 278 | 2 |

The Phase 1 audit reconciles all 803 `(source_path, test_id)` entries,
including helper/unowned Tests.  `extend_definition` ownership is transitive,
cycle/missing-reference cases fail closed, and the independent pinned-source
audit reports `source_accounted: true`.  Structural parity remains
`38` converted-Definition holds; these are not runtime-equivalence proofs.

The remaining Definition blockers are 59 unsupported, 6 converter failures,
and 4 schema/validation failures.  Highest repeated Test-side blocker reasons
include `time_difference` (30), Set/Filter Variable source shape (26),
`glob_to_regex` (20), Windows registry shape/authoring-schema failures (20 +
15), external/possible-restriction bindings (18), and bounded Variable casts
(12).  These are reported only; no missing semantics are invented.

## Same-scope 65-benchmark crosswalk

`PHASE1-SCOPE-CROSSWALK.json` compares the active 8,199-rule universe against
the historical 8,892-rule receipt using `(benchmark, source_rule)` identity:

- common active scope: **8,199** rules across 63 benchmarks;
- historical scope: **8,892** rules across 65 benchmarks;
- historical-only: **693** rules; active-only: **0**;
- source Rule SHA drift among common rules: **0**;
- status transitions: 6,479 converted→converted, 108 blocked→blocked,
  209 intentionally-excluded→intentionally-excluded, and 1,403
  manual-only→manual-only;
- native byte comparison: explicitly **not available** because both artifact
  roots were not supplied; no byte-parity claim is made.

Re-run with:

```text
python scripts/audit_self_assertion_parity.py \
  --source-root <pinned-checkout>/SCAP_1.4/OVAL_Test_Content \
  --pack <phase1-conversion-pack> --output parity.json
python scripts/build_issue28_scope_crosswalk.py \
  --active docs/evidence/issue28/ACTIVE-CANDIDATE-RULES.json.gz \
  --historical <historical-8,892-rule-receipt.json> --output crosswalk.json
```

The pinned audit receipt was built from the current pack manifest SHA
`25ab7c20dbf443786f247afa0202230d9492a32eb7e6831effafe70c84841dac` and
`tests.jsonl` SHA
`40ad04572195f615b6975689bd0940f4dfd4220d0ac52dbdd434b974d201f214`.

Two independent full-corpus rebuilds were byte-identical for the authoritative
ledgers (`definitions.json` SHA
`e1c64c85fbfff81a4e30b3455800b3479d62a4273b365fed276a075f0657bdf3`,
`tests.jsonl` SHA
`40ad04572195f615b6975689bd0940f4dfd4220d0ac52dbdd434b974d201f214`) and
all non-manifest artifacts.

Crosswalk input hashes: active rules gzip
`c5ca74bdc90fb900ebe51aa3ba94d5a2dcb03507b3c7f37ee8e97de4a849a218`;
historical 8,892-rule receipt
`eb5761140a68e7070dcab4cfd78c0d9ab75aeedbfa60cb3b423f97cb2d65f328`.
