# Issue #28 complete ledger result

This ledger was regenerated from the original 65 signed Q3 2026 ZIPs against
schema commit `7354a24cdbfe18321153ccaef5d772801a10cd71`, with owner-approved native recovery (`all_exist` and bounded Input/Parameter bindings) enabled. The 8,892 source Rule
baseline reconciles exactly and the categories are mutually exclusive.

| Category | Rules |
|---|---:|
| Automated converted, independently proved | 0 |
| Automated converted, unproved | 6,524 |
| Manual-only | 1,581 |
| Genuinely blocked | 578 |
| Intentionally excluded (four SQLEXT SQL benchmarks) | 209 |
| **Total** | **8,892** |

Automated conversion remains `CONVERTED_UNVERIFIED`; the ledger does not claim
compiler or scanner equivalence. OCIL-only Rules are manual-only, and mixed
OVAL/OCIL Rules prefer OVAL while retaining manual alternatives. Access-token
capabilities remain explicit blockers. The JSON ledger retains source ZIP hashes,
per-benchmark counts, root-cause blockers, and representative source Rules.

## Separate diagnostic statistics

These are source-feature statistics, not additional mutually-exclusive Rule
categories:

- Deprecated OVAL Tests: legacy `accesstoken_*` occurs in 127 non-excluded source Rules (125 are the primary blocker); legacy `wmi_*` occurs in 37 Rules (20 test and 14 object primary blockers).
- WMI57 supported mapping: 169 non-excluded Rules use `wmi57_*`.
- `count`: 37 Rules. This is a supported native-language direction with a missing converter/compiler mapping, not a deprecated capability.
