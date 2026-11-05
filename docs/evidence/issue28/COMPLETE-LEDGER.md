# Issue #28 complete ledger result

This ledger was regenerated from the original 65 signed Q3 2026 ZIPs against
schema commit `7354a24cdbfe18321153ccaef5d772801a10cd71`. The 8,892 source Rule
baseline reconciles exactly and the categories are mutually exclusive.

| Category | Rules |
|---|---:|
| Automated converted, independently proved | 0 |
| Automated converted, unproved | 4,517 |
| Manual-only | 1,581 |
| Genuinely blocked | 2,585 |
| Intentionally excluded (four SQLEXT SQL benchmarks) | 209 |
| **Total** | **8,892** |

Automated conversion remains `CONVERTED_UNVERIFIED`; the ledger does not claim
compiler or scanner equivalence. OCIL-only Rules are manual-only, and mixed
OVAL/OCIL Rules prefer OVAL while retaining manual alternatives. Access-token
capabilities remain explicit blockers. The JSON ledger retains source ZIP hashes,
per-benchmark counts, root-cause blockers, and representative source Rules.
