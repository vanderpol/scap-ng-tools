# Issue #59 — single 0.4.1 semantic-pack qualification evidence

Run date: 2026-11-13. Branch: `codex/issue59-single-v041-semantic-pack`.

## Exact pins

- Canonical schema PR #65 head: `0732b56567e7120ed6cb00908dff40716f76fac9`.
- Flat schema family: **145 JSON resources**, **35 root schemas**, **100 supported mappings**.
- Schema aggregate SHA-256: `578315d1e00bd39449ed597ed3d39555384276bd36198a54ca0b1e3c17e72829`.
- Semantic pack: `contracts-0.4.1.json`, 589409 bytes, SHA-256 `2903f815f04b0913b886a685f91a8d34f4125e117bc747dbf824ddd073a64629`.
- Pack format: `scap-ng-portable-0.4.1-semantic-pack/1`.
- Build inputs: OVAL Community v5.12.3 `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`; generator provenance `d12a644f4607cdc9c9ada50e3a96d4fd0060c6d9`.
- Pack regeneration was byte deterministic (two builds produced the same digest).

## Test suite and full 65-benchmark conversion

`PYTHONPATH=src:. ./.venv/bin/pytest -q`: **165 passed, 22 skipped, 48 subtests passed**.


Pinned source set: `niwc-atlantic/scap-content-library@8c8e5dff860af6b1290ee9273a282db24278f8d5`; source ZIP hashes are retained in `full65-conversion-v041.json`.

| source Rules | native documents | converted (unverified) | blocked | manual-only |
|---:|---:|---:|---:|---:|
| 8892 | 23632 | 6732 | 507 | 1653 |

Blocker categories (rule-category counts, not a disjoint rule count): `unsupported-capability=272`, `schema-semantic=229`, `unsupported-construct=131`, `source-invalid=56`, `unsupported-selection=56`.

Most frequent blocker messages are unsupported Windows `accesstoken` (127), unsupported independent `sqlext` (126), unbound external Variable/`possible_restriction` (96), and unsupported OVAL check-import/result binding or complex check (56). SQL `sqlext` remains unproved and is not aliased to `sql512`.

The same-source crosswalk against the historical 0.4.0 ledger is in `full65-crosswalk.json`: all 65 names and all source SHA-256 values match. It records 0.4.1 deltas of **-196 converted, +333 blocked, +72 manual-only**; this is disclosed, not hidden by reclassification.

## Firefox Linux acceptance

The pinned Firefox Linux archive (`c8afb0321ec0db0c831ddbc617ae734b2af3369d914d5034a4595e1d4be9f3b7`) converts **30/30 OVAL-backed Rules** and preserves **3 manual-only Rules** (`SV-251545`, `SV-251550`, `SV-251560`). Multi-value `unique`/`concat` recovery is native, source ordered, and validated by the shared 0.4.1 pack.

## Standalone OVAL accounting

See `oval-accounting.json` for exact receipts. The pinned 144-file corpus has **168 Definitions / 803 Tests** after transitive `extend_definition` ownership reconciliation: **92 converted Definitions / 478 converted Tests**, **74 blocked Definitions / 323 blocked Tests**, and **2 AIX-excluded Definitions / 2 AIX-excluded Tests**. Converted entries are schema-valid and `CONVERTED_UNVERIFIED`; no scanner execution, expected outcomes, or scanner-equivalence claim is made.

## Unproved semantics / blockers

This phase does not add missing 0.4.1 semantics. Remaining blockers include unsupported OVAL capabilities (`accesstoken`, `user`, `sqlext`), external Variables and `possible_restriction`, check-import/result binding and complex checks, unsupported functions (`time_difference`; dynamic/non-literal `glob_to_regex` remains held), Variable Set/Filter standalone forms, and schema-semantic authoring mismatches. Scanner equivalence and runtime RI/SCC proof remain unproved.

## 2026-11-14 datatype recovery qualification

The follow-up exact-head rebuild against canonical `scap-ng@aece827964c785be77b088c3c61255a2d07fd9a9` is recorded in [`DATATYPE-RECOVERY.md`](DATATYPE-RECOVERY.md), [`datatype-recovery.json`](datatype-recovery.json), and [`full65-datatype-recovery-rebuild.json`](full65-datatype-recovery-rebuild.json). The historical pre-recovery receipt is retained as [`full65-pre-recovery-source-rule-rebuild.json`](full65-pre-recovery-source-rule-rebuild.json). The new candidate is **6,379 converted / 208 blocked / 1,403 manual-only** in the active 7,990-Rule scope; **10 of the original 118 datatype regressions recovered**, while **108 remain blocked**. The nonregression gate intentionally remains failed/HOLD. These are authoring qualifications only, not RI/SCC or scanner equivalence.

The standalone OVAL corpus was also rebuilt at the same schema pin; [`OVAL-DATATYPE-RECOVERY.md`](OVAL-DATATYPE-RECOVERY.md) records **97 converted Definitions / 506 converted Tests**, **69 / 295 blocked**, and **2 / 2 owner-excluded**, with 55 preserved independent parity findings and no execution/equivalence claim.

The 85 textfilecontent subexpression cases are reviewed by pattern in [`TEXTFILECONTENT-SUBEXPRESSION.md`](TEXTFILECONTENT-SUBEXPRESSION.md) with machine-readable source evidence in [`textfilecontent-subexpression-patterns.json`](textfilecontent-subexpression-patterns.json). All 20 distinct patterns retain the blocker pending an owner-approved typed Item boundary or explicit lexical conversion rule.

The remaining 23 collected-field holds (13 shellcommand subexpressions, 6 registry values, 4 environment-variable values) are audited against pinned OVAL 5.12.3 in [`REMAINING-23-COLLECTED-FIELDS.md`](REMAINING-23-COLLECTED-FIELDS.md) and [`remaining-23-collected-field-audit.json`](remaining-23-collected-field-audit.json). No conversion is implemented; original converted→blocked statuses and blocker diagnostics are preserved.

## 2026-11-15 literal function recovery cycle

The bounded literal-only `escape_regex` and `glob_to_regex` recovery is
recorded in [`literal-function-cycle.json`](literal-function-cycle.json),
[`full65-literal-functions-cycle.json`](full65-literal-functions-cycle.json), and
[`LITERAL-FUNCTION-RECOVERY.md`](LITERAL-FUNCTION-RECOVERY.md). It recovers 2
standalone Definitions and 22 Tests without changing the active schema: the
standalone corpus is now **102/168 Definitions** and **554/803 Tests**. Dynamic
function operands remain held. The full 65 source-ID gate remains **6,489
converted / 98 blocked / 1,403 manual-only**, with zero converted-to-blocked
regressions.

## 2026-11-15 static Variable Object Set adapter cycle (prior cycle)

The bounded Set adapter cycle is retained as historical context in
[`static-variable-set-cycle.json`](static-variable-set-cycle.json) and
[`STATIC-VARIABLE-OBJECT-SET-RECOVERY.md`](STATIC-VARIABLE-OBJECT-SET-RECOVERY.md).
It preserves the exact 65-benchmark source population and produced **6,489
converted / 98 blocked / 1,403 manual-only**, recovering 10 previously blocked
Rule IDs with zero converted-to-blocked regressions. The active source-ID gate
passes for this cycle. The rebuilt standalone corpus is **100/168 Definitions**
and **532/803 Tests** converted; the independent parity audit now has **zero
converted-parity failures** and exactly **2 source-invalid holds**. The
collected-field qualification and remaining source-invalid dispositions are
recorded in [`REMAINING-PARITY-HOLDS.md`](REMAINING-PARITY-HOLDS.md).
The latest standalone rebuild is byte-receipted in the cycle JSON (manifest
`a54487dee8acd78939883083a32653b21dfe8a17dbe63b649029dabc7b1d5ed9`; parity
receipt `e76473a1dbc96c7e18471f4407c23ce5a62b50615edfecf6991a3a9fd17ac4ba`).
Historical 0.4.1 receipts above remain immutable context; the literal-function
cycle receipt is authoritative for the current worktree. No execution, RI equivalence or
scanner proof is claimed. The full converter regression suite for this
worktree is **231 passed, 22 skipped, 103 subtests passed**; the focused parity
and function tests are **39 passed, 8 subtests passed**.

## 2026-11-15 enum Variable datatype recovery cycle (current)

The closed enum Variable adapter now derives native datatype from typed
literals, Variable references, and closed `unique` graphs, including canonical
typed literal arrays. It does not trust obsolete declaration-level `datatype`
and does not cast. Evidence is in [`ENUM-DATATYPE-RECOVERY.md`](ENUM-DATATYPE-RECOVERY.md)
and [`enum-datatype-cycle.json`](enum-datatype-cycle.json).

The standalone rebuild is **104/168 Definitions** and **579/803 Tests**
converted, with **zero converted-parity failures** and two source-invalid
holds. The current full-65 candidate is **6,489 converted / 98 blocked /
1,403 manual-only**, recovering 10 blocked Rules and introducing zero
converted-to-blocked regressions; source ZIP hashes and the pinned source Git
revision pass. No RI, scanner, or equivalence qualification is claimed.

## Final disposition ledger

The exact source-ID disposition ledger is in
[`FINAL-DISPOSITION-LEDGER.md`](FINAL-DISPOSITION-LEDGER.md) and
[`final-disposition-ledger.json`](final-disposition-ledger.json), rendered from
`full65-enum-cycle.json` and the reproducible standalone cycle-6 pack. The 98
benchmark blockers are all canonical-language gaps; no deprecated,
source-invalid, owner-excluded, or recoverable converter-defect Rules remain.
Standalone holds are **239 canonical-language-gap**, **19 deprecated**, **25
source-invalid**, **4 owner-excluded**, and **1 source-inventory-only**, with
zero recoverable converter defects.

The exact-head semantic-pack gate also exposed and repaired a stale generated
pack omission: canonical `unix.sshd` was present in the 0.4.1 schema/mapping
but absent from the committed pack. Regeneration now matches byte-for-byte at
53 capabilities; current pack SHA-256 is
`2903f815f04b0913b886a685f91a8d34f4125e117bc747dbf824ddd073a64629`.
