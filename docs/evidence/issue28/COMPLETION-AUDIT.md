# Issue #28 completion audit

This audit is a qualification boundary, not an equivalence claim. It is
reconciled against the pinned source corpus and schema snapshot used by the
complete ledger.

| Requirement | Authoritative evidence | Current result |
|---|---|---|
| Preserve OVAL-preferred XCCDF selection and OCIL alternatives | `tests/test_issue28_all_exist_recovery.py`; focused source traces; `OVAL-COVERAGE-MATRIX.json` | Implemented and source-traced; OCIL execution remains manual |
| Inventory all source OVAL operations and categories | `OVAL-SOURCE-INVENTORY.json`; `OVAL-COVERAGE-MATRIX.json`; `scripts/audit_oval_coverage.py` | **65 benchmarks / 8,892 Rules / 366 distinct names; every name classified** |
| Recover identity collisions, nil selectors, typed equality recursion, invalid path recursion, absence precedence, and bindings | `RECOVERY-IMPLEMENTATION-LOG.md`; `tests/test_issue28_semantic_proof.py`; source provenance in `COMPLETE-LEDGER.json` | Implemented under bounded contracts; invalid path recursion reduced 7 source Rules; independently scanner-unproved |
| Preserve count and multi-component aggregation candidates | `MULTI-COMPONENT-AGGREGATION.md`; recovery tests; raw blocker diagnostics | Candidate emitted only in recovery mode; active schema/compiler admission is missing |
| Validate generated authoring against the pinned schema | `COMPLETE-LEDGER.json`; flat-schema CI check | Rebuilt and validated; this does not prove runtime equivalence |
| Rebuild mutually exclusive accounting | `COMPLETE-LEDGER.json` and `COMPLETE-LEDGER.md` | 6,792 automated-unproved; 1,581 manual-only; 310 blocked; 209 excluded; 0 proved |
| Independently compare source OVAL and native scanner results | No compiler/scanner execution is available in this tools branch | **Not achieved; no Rule is promoted to proved** |

## Remaining language and contract gaps

The 310 blocked Rules remain grouped by root cause in
`REMAINING-ROOT-CAUSES.md`. The material unresolved decisions are:

- typed relational XCCDF Value constraints;
- admission of count, arithmetic/split/substring, and multi-component
  collection expressions in the active canonical schema/compiler/runtime;
- Registry hierarchy traversal for the one exact-key/patterned-name source
  shape;
- explicit typed casts and composed Input expressions;
- unsupported `windows.user_*`, legacy `wmi_*`, access-token, deprecated RPM
  fields, and source-specific IIS/NGINX capability mappings.

SQLEXT-dependent SQL benchmarks remain intentionally excluded with source hashes
and XML retained in `SQL-EXCLUSIONS.*`. Float recovery remains aligned with the
recorded binary32 contract, but runtime/compiler/scanner equivalence is not
claimed.
