# Issue #28 final targeted blocker audit

This report audits every active blocked Rule after the legacy-WMI and XCCDF
Value recoveries. The machine-readable companion is
`FINAL-BLOCKER-MATRIX.json`; it retains each Rule's source ZIP hash, source
Rule hash, selected checks, raw diagnostics, dependency IDs/hashes, required
capabilities, and exact primary root cause.

## Accounting

The active ledger remains 8,199 Rules:

| Status | Rules |
|---|---:|
| Automated converted, unproved | 6,479 |
| Manual-only | 1,403 |
| Genuinely blocked | 108 |
| Intentionally excluded SQLEXT | 209 |
| Independently proved | 0 |

No safe converter-only recovery was found among the 108. Every candidate that
would reduce the total requires either a missing native contract, an explicit
source-family decision, or the owner-approved 0.5 datatype design.

## Root-cause matrix

| Root cause | Rules | Disposition |
|---|---:|---|
| Deprecated AccessToken test | 66 | Intentionally unsupported |
| Deprecated RPM `md5_differs` State | 2 | Intentionally unsupported |
| Legacy WMI downstream record projection | 14 | Native language gap |
| Windows `user_test` | 5 | Native language gap |
| IIS heterogeneous Set/Filter State families | 6 | Native language gap |
| NGINX cross-family `file_test` closure | 1 | Native/source contract gap |
| Registry exact-key + patterned-name traversal | 1 | Native language gap |
| Input used inside Variable function | 1 | Native language gap |
| Variable datatype mismatches | 8 | Deferred 0.5 design |
| Variable cast boundary | 1 | Deferred 0.5 design |
| Additional IIS datatype diagnostics | 3 | Retained audit evidence; not promoted |
| **Total** | **108** | |

AccessToken and SQLEXT remain intentionally unsupported/excluded. The 8
function datatype Rules are unchanged: three arithmetic, four split, and one
count. The three additional IIS datatype diagnostics remain blocked by the
same strict-declaration policy but are not silently folded into the eight
approved function-recovery candidates.

## Legacy WMI: individual conclusion

All 14 active downstream WMI Rules have a valid structural migration of their
legacy `wmi_object`/`wmi_state` to the existing `windows.wmi.query` record
collector, but none can be admitted as a complete Assessment without changing
semantics:

| Downstream use | Rules | Representative IDs | Finding |
|---|---:|---|---|
| WMI record consumed by `end` | 2 | `SV-225230`, `SV-225235` | Existing `end` accepts scalar text, not a record member. |
| WMI record consumed by `concat` | 4 | `SV-225232`, `SV-225234`, `SV-218795`, `SV-214416` | Existing `concat` rejects the record-valued operand. |
| WMI record consumed by `substring` | 6 | `SV-259637`, `SV-259704`, `SV-224975`, `SV-205723`, `SV-254396`, `SV-278143` | Existing `substring` rejects the record-valued operand. |
| WMI-backed Variable Object with Set/Filter | 2 | `SV-218752`, `SV-214463` | Existing Variable-source contract requires one `var_ref`; Set/Filter populations and heterogeneous State families are not admitted. |

The existing WMI schema preserves namespace, WQL, named result records,
record-member comparisons, record cardinality, and field missing/error
semantics. It does **not** provide a Variable-expression record-member
projection. Flattening `result.name` into scalar `result` would lose the
record boundary and is rejected.

### Proposed owner decision (not implemented)

A concise 0.5 candidate could add a `record_member` Variable expression:

```yaml
record_member:
  source:
    values:
      object: legacy-wmi-query-object
      field: result
  member: name
  records_found: one_or_more
  records_matching: every
  values_found: one_or_more
  values_matching: every
```

The compiler/runtime contract must preserve ordered records, duplicate
members, missing member versus empty member, datatype, and `error`/`unknown`
propagation. A missing member cannot become an empty collection. This requires
independent OVAL vectors before any Rule is promoted.

## Other shared roots

- `windows.user` is not interchangeable with `windows.user_sid`: the five
  Rules use username pattern selection plus group, enabled, and password-age
  State fields. A SID-only mapping is not faithful.
- IIS Set/Filter failures mix `appcmd`, environment-variable, and related State
  families. Existing native Set filters require one capability family; dropping
  filters changes the population.
- The NGINX Rule's `unix:file_test` references `independent:shellcommand`
  Objects/States. Remapping it to shellcommand would alter the source Test
  family and needs an explicit source/capability contract.
- The two RPM Rules use deprecated `md5_differs`; existing `filedigest_differs`
  is not a source-preserving substitute.
- Registry traversal requires exact-key selection plus patterned-name
  recursion. Removing traversal changes the Object population.
- Organizational Inputs are supported only as direct typed operands. Composing
  an Input inside OVAL `substring` requires an explicit evaluation/status
  contract.

## Prioritized next step

1. Build an executable SCAP-NG reference evaluator for the existing 0.4
   record/cardinality/status model, beginning with `windows.wmi.query` and
   independent Variable-expression vectors.
2. Add an independent OVAL oracle fixture runner against the pinned 5.12.3
   source examples, comparing values, population, cardinality, and
   error/unknown outcomes—not just YAML or compilation.
3. Use those vectors to decide the 0.5 `record_member`, variable-source
   Set/Filter, and typed-cast contracts.
4. Only then revisit `windows.user`, heterogeneous IIS filters, and the NGINX
   cross-family source shape.

No compiler/scanner executable was available in this recovery workspace. This
report therefore makes no executable or independent-equivalence claim.
