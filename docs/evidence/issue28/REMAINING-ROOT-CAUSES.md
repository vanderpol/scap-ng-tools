# Issue #28 remaining root causes

This is the final pinned-ledger grouping for the current recovery round. The
primary counts are mutually exclusive; dependency diagnostics in the complete
JSON ledger may overlap a Rule and are not added to the primary total.

| Root cause | Primary Rules | Classification | Notes |
|---|---:|---|---|
| Access-token OVAL Test/Object/State | 125 | Intentionally unsupported / deprecated | Source inventory has 127 non-excluded Rules. No native equivalent is fabricated. |
| Legacy `wmi_*` | 34 | Intentionally unsupported / deprecated | 20 primary Test Rules and 14 primary Object Rules; 37 source Rules tracked. `wmi57_*` remains supported. |
| XCCDF relational Value operator | 36 | Genuine native-contract gap | Requires typed Input/Parameter relation semantics; allowed-values-only lowering is not faithful. |
| Multi-component aggregation | 30 | Genuine native-contract gap | Requires an ordered collection-union expression; concat or set union would change OVAL semantics. |
| Float ordered comparisons | 10 | Pending canonical contract | Precision, NaN/infinity, lexical errors, and comparison behavior must be fixed before conversion equivalence. |
| Windows `user_*` capability | 8 | Genuine capability gap | No approved `windows.user` mapping exists in the pinned SCAP-NG 0.4 contract. |
| Pattern-path recursion with traversal attributes | 7 | Genuine source/native boundary | Typed equality recursion is recovered; pattern paths, full paths, and upward recursion remain fail-closed. |
| XCCDF/OVAL datatype mismatch | 2 | Source semantic mismatch | XCCDF string Values are exported to OVAL binary Variables; no silent cast is applied. |
| Deprecated RPM `md5_differs` State | 2 | Intentionally unsupported | The pinned mapping explicitly replaces this deprecated field with `filedigest_differs`; no equivalent is invented. |
| Native function contract admission | 64 | Pending canonical schema/compiler | Converter emits validated recovery envelopes for arithmetic, count, split, substring, and nested forms, but the pinned Assessment schema does not yet admit all function calls. |
| Other native capability mismatches | 5 | Genuine capability/mapping gaps | IIS/NGINX state capability mismatches remain source-specific and require approved mappings. |
| Native Variable cast | 1 | Genuine semantic gap | Requires explicit typed cast/error propagation semantics. |
| Assessment Input function composition | 1 | Genuine semantic gap | Native Input cannot currently participate in a composed Variable expression without a typed expression contract. |

The ledger classification is **6,775 automated converted but unproved, 1,581
manual-only, 327 genuinely blocked, 209 intentionally excluded, and 0
independently proved** out of 8,892 Rules. YAML/schema admission and compilation
are not proof; independent scanner/source-semantic proof remains outstanding
for every converted Rule.
