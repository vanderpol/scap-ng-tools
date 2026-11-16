# Issue #59 final disposition ledger

This ledger is rendered from the exact-head full-65 receipt and the already-generated standalone pack. It is not a new source audit.

Pins: schema `0.4.1` / `aece827964c785be77b088c3c61255a2d07fd9a9`, benchmark source `8c8e5dff860af6b1290ee9273a282db24278f8d5`, standalone source `e3538595c5083b9c34d937a81d319234df9bbfaa`.

## Benchmark Rules

**98 blocked Rules**; candidate **6489 converted / 98 blocked / 1403 manual-only**; nonregression **PASS** (0 converted→blocked).

| Disposition | Count |
|---|---:|
| `canonical_language_gap` | 98 |
| `deprecated` | 0 |
| `owner_excluded` | 0 |
| `recoverable_converter_defect` | 0 |
| `source_invalid` | 0 |

All 98 benchmark blockers are canonical-language gaps in the active 0.4.1 contract; none are deprecated, source-invalid, owner-excluded, or recoverable converter defects. Exact benchmark/source Rule IDs and diagnostics are in the JSON ledger.

## Standalone OVAL holds

The ledger carries **64 Definition rows** and **224 Test rows** (blocked plus the authorized AIX exclusions). Converted parity failures: **0**; source-invalid parity holds: **2**.

| Disposition | Count |
|---|---:|
| `canonical_language_gap` | 239 |
| `deprecated` | 19 |
| `owner_excluded` | 4 |
| `recoverable_converter_defect` | 0 |
| `source_invalid` | 25 |
| `source_inventory_only` | 1 |

- `deprecated`: explicitly deprecated recursion direction and Solaris `package511_test`.
- `source_invalid`: invalid source child shape/namespace, invalid integer lexical value, invalid Object notes child, or out-of-pin OVAL 5.10.1 source document.
- `owner_excluded`: exactly the two AIX Definitions and two AIX Tests authorized by `issue-56:aix-excluded`.
- `source_inventory_only`: one unowned helper Test; it is not a conversion claim.
- `canonical_language_gap`: valid source behavior without a lossless active 0.4.1 representation; no casts or equivalence are invented.

Every row preserves the original source path, ID, source SHA-256, status, and diagnostic in `final-disposition-ledger.json`.
