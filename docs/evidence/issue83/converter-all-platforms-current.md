# Complete 785-Test source-witness conversion ledger

This ledger joins all source-platform cohorts in the pinned OVAL Self-Assertion
corpus through the production converter using exact flat 0.4.1 schema preflight.
It is authoring conversion evidence only, not expected-result, runtime, or
independent-equivalence proof.

Pins:

- Source `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`
- Canonical schema `5ee55288b369da26f308f40813e545b78dff2753`
- Schema family `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`
- Witness receipt `d4741fdae77705015bdbe060f5be8b35ea88cc01b7cf0062660fd7ddec32018e`

## Same-denominator results

| Platform prefix | Tests | Converted | Blocked |
|---|---:|---:|---:|
| agnostic | 328 | 308 | 20 |
| linux | 62 | 62 | 0 |
| unix | 72 | 71 | 1 |
| windows | 218 | 203 | 15 |
| macos | 43 | 12 | 31 |
| ios | 16 | 0 | 16 |
| solaris | 21 | 9 | 12 |
| iosxe | 17 | 4 | 13 |
| asa | 2 | 0 | 2 |
| junos | 2 | 0 | 2 |
| panos | 2 | 0 | 2 |
| aix | 2 | 0 | 2 |
| **Total** | **785** | **669** | **116** |

The agnostic blockers are 18 canonical external-Variable input holds and two
source-invalid typed literals. Unix `tst:466` is the deprecated upward
recursion source case. Windows blockers are separately classified schema,
unsupported-source and source-policy cases. Other non-Linux platform failures
are diagnostic and do not imply runtime support.

Per-platform receipt paths and hashes are in the machine-readable JSON ledger.
