# Issue #28 active candidate ledger

This is the rebuilt candidate ledger after integrating the OVAL variable
function contract and excluding Windows Server 2012/2012 R2 from active
modernization. The historical all-65 audit and original ZIP provenance remain
separate. The compressed Rule record companion contains one record per active
Rule; it is not source content and does not replace the preserved historical
ledger.

## Active accounting

| Classification | Rules |
|---|---:|
| Automated converted, independently proved | 0 |
| Automated converted, unproved | 6,473 |
| Manual-only Assessment | 1,403 |
| Genuinely blocked | 114 |
| Intentionally excluded SQLEXT | 209 |
| **Total** | **8,199** |

Compared with the active pre-integration baseline, **82 Rules were recovered**:
6,391 → 6,473 converted; 196 → 114 blocked. None are independently proved.

## Function recovery

| Function/recovery | Historical candidate blockers | Recovered | Still blocked |
|---|---:|---:|---:|
| `count` | 37 | 36 | 1 |
| Multi-component aggregation | 30 | 30 | 0 |
| `split` | 19 | 15 | 4 |
| `arithmetic` | 3 | 0 | 3 |
| `substring` | 1 | 1 | 0 |
| **Total** | **90** | **82** | **8** |

The eight residual function Rules are explicit datatype-boundary cases, not
schema-shape failures: one `count` result is declared string, four `split`
results are declared integer, and three arithmetic results are declared
string. No silent cast was added.

## Active blocker inventory

The mutually exclusive active Rule-level primary blocker counts are in the JSON
ledger. Important remaining groups include:

- AccessToken: 66 primary Rules remain (Windows 10 and Windows Server 2016).
  The source audit has 66 supported-platform AccessToken Rules; 59 of the
  historical 125 primary AccessToken blockers were in the excluded benchmarks.
- Legacy WMI: remaining diagnostics are retained as unsupported; no WMI
  equivalence is claimed.
- XCCDF Value constraints: 5 active Rules still require the typed constraint
  adapter.
- Other remaining gaps include unsupported `user_*`, State/capability
  mismatches, traversal admission, Input composition, and the eight explicit
  function datatype boundaries.

Diagnostic feature counts may overlap, but the `genuinely_blocked: 114`
classification is mutually exclusive and authoritative.

## Qualification boundary

Schema validation, semantic validation, conversion, and ledger generation pass
for this candidate. Runtime/compiler/scanner equivalence and independent OVAL
proof remain unclaimed. AccessToken and SQLEXT remain intentionally unsupported;
all source IDs, manual alternatives, and provenance are retained.
