# Static Variable Object Set recovery

This increment keeps the active SCAP-NG 0.4.1 schema pin unchanged and fixes the
converter adapter for the bounded, source-static subset of OVAL Variable
Objects.

## Contract

The adapter materializes only a finite `variable_object` whose operands are
constant Variables and whose Set contains no Filters. It preserves the OVAL
5.12.3 Set operator (`UNION`, `INTERSECTION`, or relative `COMPLEMENT`),
operand order, first-occurrence ordering and the 4,096-value resource bound.
Nested Sets are traversed recursively. A base-namespace `var_ref` is accepted;
it is the namespace used by the OVAL 5.12.3 Variable/Object grammar.

This is authoring conversion only. It does not collect host data, evaluate a
Filter, or assert RI/scanner equivalence. Dynamic Variables, Filter-bearing
Sets, mixed datatypes, cycles and oversized populations remain blocked rather
than being converted to an empty or UNKNOWN result.

## Pinned source evidence

- OVAL Community 5.12.3, commit `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`.
- `oval-definitions-schema.xsd` defines Set as recursive and permits one or
two nested Sets or Object references; UNION, INTERSECTION and COMPLEMENT are
binary/ordered operators.
- Existing Issue #59 source witness set: `oval-accounting-operation-directed.json`
(144 XML files, 168 Definitions and 803 Tests). The exact per-source IDs and
hashes remain in the signed-source ledgers; this change does not alter source
identity or disposition policy.

## Executable vectors

`tests/test_issue59_native_function_lowering.py` covers:

- base-namespace constant `var_ref` plus nested intersection/union, including
ordered first-occurrence output;
- Filter-bearing Sets, dynamic Variable operands and the fail-closed path.

The tests validate syntax and source graph boundaries only. They do not replace
the independent OVAL/RI parity gate.

## Cycle receipt (2026-11-15)

The reproducible cycle receipt is `static-variable-set-cycle.json`. All 65 ZIP
SHA-256 pins were verified; the local source checkout did not expose the pinned
source Git object, so that separate Git-revision gate is explicitly unverified.
Against the
fixed 65-benchmark source set it records **6,489 converted / 98 blocked /
1,403 manual-only** in the 8,892-Rule population, with **10 blocked-to-converted
recoveries and zero converted-to-blocked regressions**. The active 7,990-Rule
source-ID nonregression gate therefore passes for this cycle.

The standalone rebuild records **100/168 Definitions** and **532/803 Tests**
converted, with **zero converted-parity failures and two source-invalid
holds**. Source accounting passes; the typed collected-field disposition is
recorded in `REMAINING-PARITY-HOLDS.md`. The latest rebuilt pack and parity
receipt hashes are in `static-variable-set-cycle.json`. Execution/scanner
equivalence remains unverified. This receipt is not a release qualification.
