# Approved exact-source absence corrections — 2026-11-03

The owner replied **“Approved”** to extending the bounded correction recommended
in [PR20's decision packet](ISSUE14-ABSENCE-DECISION.md) to its seven remaining
Rules. [The authorization record](https://github.com/vanderpol/scap-ng-tools/issues/14#issuecomment-6615375024)
identifies the exact scope and qualifications. This successor implements that
approval; the earlier packet and evidence remain historical, unchanged records.

These are **owner-corrected native drafts**. Comparator-free native field absence
is accepted as the intended corrected policy for these exact sources. No
general lossless comparator-elision identity or new evaluation semantics are
adopted. The original-OVAL equivalence and scanner-proof flags remain false.

## Bounded behavior and provenance

`--approved-absence-corrections` explicitly enables the eight-case profile:
the previously approved Oracle9 correction plus the seven newly approved cases.
Without this flag, ordinary recovery still blocks all eight. The existing
`--approved-oracle-absence` profile still recovers only Oracle9; its documents
and correction warning remain identical, including when both flags are used.

| Newly approved Rule | Source Benchmark | Original field |
| --- | --- | --- |
| SV-237770r991589 | Ubuntu18.04 | stdout_line |
| SV-248641r991589 | Oracle Linux8 | stdout_line |
| SV-230322r1017133 | RHEL8 | stdout_line |
| SV-230323r1017134 | RHEL8 | stderr_line |
| SV-217172r1184438 | SLES12 | stderr_line |
| SV-234992r1184471 | SLES15 | stderr_line |
| SV-252961r991589 | TOSS4 | stdout_line |

Each original string State entity has `check_existence="none_exist"`,
`operation="pattern match"` and operand `.*`. Only the generated scalar native
predicate becomes `{values_found: none}`. The original archive, Rule, full
four-node OVAL closure, commands, selection, Item requirements and manual
Assessment remain preserved. Original Test `check_existence="any_exist"` and
`check="all"` remain represented by the established native projection.

[The seven-case authorization manifest](../src/scap_ng_tools/converter/approved_absence_cases.py)
pins each ZIP, full parsed Rule, component/Definition binding, all Definition,
Test, Object and State hashes, and the exact field hash. The converter attests
them on activation and again at predicate use. Changed graphs, commands,
attributes, operands, archive pins, other Rules and selector/record contexts do
not activate the correction. This is a source-specific opt-in, not a regex
heuristic or a broader exception to strict conversion.

Trace warnings preserve the original entity/operand, all node hashes, corrected
predicate and approval link, with `source_correction: true`, `owner_normalized:
true`, `independent_static_proof: UNPROVED` and `scanner_evaluated: false` for the
new seven. Recovery/triage rows explicitly label the corrected drafts. The older
Oracle warning retains its previous approved-correction identity. All eight
manual document hashes and source automatic/manual defaults remain identical.

## Ledger and evidence

| Scope | PR20 | This approved profile |
| --- | --- | --- |
| Eight comparator-bearing absence cases | 1 corrected draft /7 blocked | 8 corrected drafts /0 blocked |
| Remaining blocker ledger | 34 | 27 |
| Fresh48 candidate ledger | 14 drafts /34 blocked | 21 drafts /27 blocked |
| Conditional selected143 roll-up | 89 automated /20 manual /34 blocked | 96 automated /20 manual /27 blocked |
| Historical native-draft blocker backlog | 370 | 363 |
| Independently proved lossless comparator elisions | 0 | 0 |

The [fresh eight-case replay](evidence/issue14-approved-absence/recovery.json)
records pins, manual hashes, corrections and before/after status. The
[fresh48 ledger](evidence/issue14-approved-absence/remaining48.json) changes
exactly the seven approved rows; the other41 statuses and all48 manual-preservation
flags remain unchanged. Counts for143 and the historical backlog are conditional
roll-ups of retained prior receipts plus these bounded deltas, not fresh full
corpus verification. The prior35 ledger therefore moves to27 through the Oracle
correction in PR20 and these seven corrections.

[Local validation](evidence/issue14-approved-absence/validation.json): **87 portable
tests pass with zero skips**, including all535 strict Rule goldens, old profile
behavior, eight manual hashes, all28 newly guarded closure-node mutations,
Rule/pin/context negatives and post-attestation mutation checks. Five focused
absence tests pass against unchanged native
`855c6023d55d882b55c0507d5492e6f4e4946023`.

[Native qualification](evidence/issue14-approved-absence/native.json) freshly
compiles and independently checks **7 bounded packages,38 documents,8 programs,
8 Tests and8 manual Assessments**. Sixteen capability/cardinality program mutants
are rejected. Package/source/program identity is established only for the
corrected native drafts. This does not execute collectors or establish original
OVAL/scanner equivalence, publisher trust or release readiness. Conversion-ledger
compiled/proof flags are not upgraded by these separate qualification receipts.

Frozen runtime/semantic modules, schema/contract pins, source fixtures, prior
proofs and workflows are unchanged. The binary32 API-record coverage defect
**C1 remains a coordinated merge blocker**; this work neither edits nor clears
the reviewed producer/consumer PRs. No merges, Editor36, release preparation,
mandatory six-Benchmark transfer changes, quota retries or full65 run occur.

## Reproduction

Use the existing exact CI inputs: canonical schema
`246a8d37cc54875386768a7d76b60a6f9c01d013`, binary32 sidecar
`da4c48dfc60dc96a46e7b85425f70fb8f301a0b1`, official OVAL
`2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`, and signed NIWC archives at
`8c8e5dff860af6b1290ee9273a282db24278f8d5`. Export the same test environment
variables as the [prior recipe](ISSUE14-ABSENCE-DECISION.md#reproduction).
With `PYTHONPATH=src`, use fresh output directories:

```sh
python -m unittest discover -s tests -v
python scripts/recover_approved_absence_cases.py --schema-root "$SCAP_NG_SCHEMA_ROOT" --source-root "$SCAP_NG_ADDITIONAL_FIXTURES_ROOT" --output /tmp/approved-absence-replay
python scripts/triage_recovery_blockers.py --schema-root "$SCAP_NG_BINARY32_SCHEMA_ROOT" --source-root "$SCAP_NG_ADDITIONAL_FIXTURES_ROOT" --binary32-comparisons --approved-absence-corrections --output /tmp/approved-absence-ledger
python scripts/qualify_approved_absence.py --compiler-root /path/to/pinned-native --compiler-commit 855c6023d55d882b55c0507d5492e6f4e4946023 --recovery /tmp/approved-absence-replay --output /tmp/approved-absence-native
```

The last command is optional and requires the private pinned toolchain. Public
runtime and CI have no private dependency. Large local logs and generated native
packages stay outside Git; compact hashes and exact-head CI links are retained.
