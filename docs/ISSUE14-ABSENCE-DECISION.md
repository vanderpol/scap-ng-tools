# Eight comparator-bearing absence cases — 2026-11-03

**No general lossless comparator-elision fix is established.** All eight original
sources were inspected, with exact pins and full four-node OVAL closures in
[the investigation](evidence/issue14-absence/investigation.json). One existing
owner-authorized Oracle9 correction is now available through a separate explicit
opt-in. The other seven remain blocked pending the decision below. No new
language/evaluation semantics are implemented by this PR.

## Exact original source and cardinality

All are signed Q3 NIWC archives at `8c8e5dff860af6b1290ee9273a282db24278f8d5`.
Each Rule reaches one Definition, one shellcommand Test/Object/State, and one
absence field. Tests explicitly use `check_existence="any_exist" check="all"`.
The State field explicitly has `check_existence="none_exist" operation="pattern
match"` and scalar text `.*`; datatype defaults to string, entity_check defaults
to all, and there is no Variable operand. Test existence, State-entity existence,
State operator and Item/field/value quantifiers remain separate scopes.

| Original Rule | Benchmark | State field | This successor |
| --- | --- | --- | --- |
| SV-237770r991589 | Ubuntu18.04 | stdout_line | blocked |
| SV-248641r991589 | Oracle Linux8 | stdout_line | blocked |
| SV-271844r1184222 | Oracle Linux9 | stderr_line | existing owner correction, explicit opt-in |
| SV-230322r1017133 | RHEL8 | stdout_line | blocked |
| SV-230323r1017134 | RHEL8 | stderr_line | blocked |
| SV-217172r1184438 | SLES12 | stderr_line | blocked |
| SV-234992r1184471 | SLES15 | stderr_line | blocked |
| SV-252961r991589 | TOSS4 | stdout_line | blocked |

[Exact ZIP/Rule pins](../tests/fixtures/issue14-absence-pins.json) and the pooled
XML identities preserve all attributes, commands, Definition/Test/Object/State
bindings and original manual-document hashes. The shellcommand collector is the
NIWC extension; no host command, collector or scanner was executed. Its entity
types inherit the OVAL base rules, but third-party component observations are
not a proof of the SCC collector's complete behavior.

## What the normative tables establish — and what they do not

Pinned official OVAL5.12.3 at `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706` defines
State-entity existence separately from Test-level existence. For none_exist:

| Corresponding entity population | Existence piece |
| --- | --- |
| at least one exists, even with errors/not-collected | false |
| zero exists, at least one error | error |
| zero exists/errors, at least one not-collected | unknown |
| zero exists/errors/not-collected (including zero or more does-not-exist) | true |

The generic chart explicitly covers the zero population; State base-type prose
also gives a one-or-more does-not-exist example. Neither is sufficient to invent
the subsequent value-comparison aggregate. The official ALL result chart has
**no all-zero row**. The maintained current-design record explicitly says its
existence helper stops before zero-entity value aggregation. This uncertainty
is an engineering lack of an adopted rule, distinct from the normative
`unknown` result caused by not-collected data.

[Independent witnesses](evidence/issue14-absence/status-witnesses.json) parse the
pinned chart itself and compare81 populations with a separately written status
model. Existing empty strings/newlines still count as existing entities:
`.*` matches them but none_exist is false. A universal regex does not convert a
present value into an absent field or override error/unknown evidence.

An additional [upstream component experiment](evidence/issue14-absence/reference-components.json)
pins OpenSCAP `099cd84a0fa23c0e5d748e4e577c900c9b280623` and compiles its two
unmodified counter/aggregate functions with named-enum stubs. It returns true
for empty existence, but **unknown** for empty ALL comparisons. Its inspected
`_evaluate_sysent` returns false for a does-not-exist entity; the aggregate
component returns false for that scalar false, even though none_exist is true.
Comparator-free native absence would retain the true existence piece instead.
This is a concrete reason not to infer blanket equivalence from `.*`.

The experiment does not run the full OpenSCAP evaluator or SCC extension. In
particular the inspected upstream full-item loop counts statuses before filtering
entity names, so this packet does not present it as an authoritative complete
implementation of the source cases. The official empty-aggregate gap remains
unresolved here; no component experiment is promoted into new normative behavior.

## Existing syntax and bounded approved recovery

Approved native0.4 permits comparator-free `{values_found: none}` and forbids a
meaningful comparator on that absence. Splitting absence and regex into two
ordinary field predicates does not solve nonvacuous cardinality/unknown behavior.
All eight experimental absence-only Assessment projections pass current syntax;
these are explicitly **UNQUALIFIED** and are never emitted as production Rules.

There is already a separate owner-approved source correction for Oracle9
SV-271844, dated2026-10-24, recorded in the immutable
[earlier packet](https://github.com/vanderpol/scap-ng-research/blob/855c6023d55d882b55c0507d5492e6f4e4946023/docs/audit/v04-six-stig-current-schema-20261024.md)
and its source-attested migration. This correction removes only that exact
operand from generated NG; it is not a general semantic identity.

`--approved-oracle-absence` consumes only that existing authorization. It checks
the original ZIP, full Rule, component/Definition binding and every Definition,
Test, Object and State parsed-node hash, and rechecks at predicate use. Other
Rules, archives, changed commands/graphs/attributes/patterns and selector/record
contexts retain their previous strict failures. The XML is untouched. Trace
includes the original source entity, removed operand, native predicate, decision
and source-correction qualification. Default recovery remains unchanged.

That one corrected Rule retains its original automatic default and byte-identical
manual Assessment. Native compilation/package/source/program identity passes:
five documents, one program, one Test; two divergent native-program mutants are
rejected. This is a **source-corrected native DRAFT**, not independently proved
original-OVAL or scanner equivalence. Original proof/compiled flags are not
silently promoted in conversion output.

## Before/after ledger and compatibility

| Scope | PR19 baseline | With exact approved correction |
| --- | --- | --- |
| Eight absence cases | 8 blocked | 1 owner-corrected draft /7 blocked |
| Lossless comparator-elision proofs | 0 | 0 |
| Prior35 blocked cases | 35 | 34 |
| Fresh48 candidate ledger | 13 drafts /35 blocked | 14 drafts /34 blocked |
| Conditional selected143 roll-up | 88 automated /20 manual /35 blocked | 89 automated /20 manual /34 blocked |
| Native-draft historical blocker backlog | 371 | 370 |

[Fresh ledger](evidence/issue14-absence/remaining48.json) labels the Oracle row
with its exact source-correction warning. All eight manual hashes are preserved;
seven stay standalone beside blocked automatic defaults. Earlier ledgers/proofs,
143 schema JSONs, strict18-file runtime, four frozen semantic modules, binary32
contract/pins,235-resource metadata proof and manual Assessments are unchanged.
No full143 or full65 proof/recompilation is inferred from these bounded deltas.
The independent [binary32 review](ISSUE14-BINARY32-REVIEW.md) separately identifies
a merge blocker; native syntax qualification of this scalar absence case does
not resolve that unrelated API-record coverage defect.

[Bounded recovery delta](evidence/issue14-absence/recovery.json) records each
Rule's before/after status, original source/manual hashes and correction label.
[Local validation](evidence/issue14-absence/local-validation.json) records code
and log hashes: **82 portable tests, zero skips; five focused absence tests;
26 tests against the unchanged native head**, all passing. The final48 CLI
passes after its missing-binding guard adjustment. Exact pushed-head CI is
reported separately in the PR, without implying private artifact retention.

## Reproduction

Use the exact repository commits in the source inventory and binary32 review.
With `PYTHONPATH=src`, set `SCAP_NG_SCHEMA_ROOT` to canonical246a8d37,
`SCAP_NG_BINARY32_SCHEMA_ROOT` to canonicalda4c48df,
`SCAP_NG_OVAL_ROOT` to official OVAL2f140ee5,
`SCAP_NG_ADDITIONAL_FIXTURES_ROOT` to the pinned NIWC `Archive/2026_Q3`, and
`SCAP_NG_SOURCE_FIXTURE` to its Windows Server2025 ZIP. Run:

```sh
python -m unittest discover -s tests -v
python scripts/investigate_absence_cases.py --schema-root "$SCAP_NG_SCHEMA_ROOT" --source-root "$SCAP_NG_ADDITIONAL_FIXTURES_ROOT" --output /tmp/absence-source-fresh
python scripts/absence_witnesses.py --oval-root "$SCAP_NG_OVAL_ROOT" --output /tmp/absence-status-fresh.json
python scripts/triage_recovery_blockers.py --schema-root "$SCAP_NG_BINARY32_SCHEMA_ROOT" --source-root "$SCAP_NG_ADDITIONAL_FIXTURES_ROOT" --binary32-comparisons --approved-oracle-absence --output /tmp/absence-ledger-fresh
```

Output paths must be new. The optional upstream C-component experiment takes
`--openscap-root` at099cd84a and `--output` (a new JSON path). The optional
binary32 reproducer takes `--compiler-root` at native855c6023 and `--output`.
These experiments do not run providers or a scanner. Native qualification uses
the existing `qualify_recovery_with_toolchain.py` against855c6023 and only the
Oracle five-document corrected-source set; its receipt is linked above.

## Owner decision required for the remaining seven

1. **Recommended for bounded recovery: explicitly authorize the same source-pinned
   correction for the seven listed Rules**, accepting comparator-free native
   field absence as their intended corrected policy. Preserve every original
   pin/operand/quantifier and mark them owner-normalized drafts. This extends a
   source correction, **not a claim of lossless original-OVAL equivalence**.
2. Keep all seven blocked until authoritative source/evaluator guidance and
   independent conformance evidence resolve the zero-value aggregate and the
   native contract is reviewed. This is the source-preserving default now.
3. Introduce new comparator-bearing absence syntax and explicit evaluation/
   cardinality/status semantics. This requires a separate coordinated language,
   compiler/consumer/validator contract; syntax alone would not settle the gap.

No implementation of alternatives1 or3 for the seven unapproved cases is included.
Decision: **pending**. Strictness, source pins, manual methods and proof levels
remain protected while that decision is outstanding. No merge, release, Editor36,
mandatory transfer changes or quota retries are included.
