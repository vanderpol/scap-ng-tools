# Issue #28 active candidate ledger

This is the rebuilt candidate ledger after integrating the OVAL variable
function recovery, typed XCCDF Value relations, and the bounded legacy-WMI
migration. Windows Server 2012/2012 R2 remain historical-only. The historical
all-65 audit and original ZIP provenance remain separate.

## Active accounting

| Classification | Rules |
|---|---:|
| Automated converted, independently proved | 0 |
| Automated converted, unproved | 6,479 |
| Manual-only Assessment | 1,403 |
| Genuinely blocked | 108 |
| Intentionally excluded SQLEXT | 209 |
| **Total** | **8,199** |

Six previously blocked active Rules are recovered: five XCCDF Value relation
Rules and one direct legacy-WMI Rule. None are independently proved.

## Recovery counts

| Recovery | Historical active candidates | Recovered | Remaining |
|---|---:|---:|---:|
| `count` | 37 | 36 | 1 |
| Multi-component aggregation | 30 | 30 | 0 |
| `split` | 19 | 15 | 4 |
| `arithmetic` | 3 | 0 | 3 |
| `substring` | 1 | 1 | 0 |
| **Function total** | **90** | **82** | **8** |
| Legacy WMI migration candidates | 15 | 1 | 14 |
| XCCDF Value constraints | 5 | 5 | 0 |

Legacy WMI migration is not counted as 15 recovered Rules: the 14 remaining
Rules use WMI results through unsupported scalar Variable/function or Set
shapes. Their WMI query projection is retained only where the resulting native
Assessment remains valid.

## Remaining active blocker groups

- AccessToken: 66 primary Rules on supported platforms; intentionally
  unsupported for automatic conversion.
- Legacy WMI downstream record/scalar boundaries: 14 Rules remain blocked after
  capability migration; no scalar `result` flattening is fabricated.
- OVAL function datatype boundaries: eight Rules remain deferred under the
  Issue #28 0.4 strict-datatype decision (3 arithmetic, 4 split, 1 count).
- Other capability/converter roots: five `user_test` Rules, two variable-source
  Set/Filter Rules, two State-field gaps, one traversal admission, one bounded
  cast boundary, one NGINX state mismatch, six IIS state mismatches, and five
  other native schema/function admission Rules.
- SQLEXT: 209 Rules intentionally excluded from active modernization.

## Qualification boundary

The candidate artifacts are schema-validated, converter-tested, and ledger
reconciled. No Rule is independently proved by this ledger; compiler and
scanner execution is not claimed. Source Rule IDs, check selection, manual
alternatives, provenance, and historical artifacts are retained.
