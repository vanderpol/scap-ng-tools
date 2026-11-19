# Full pinned OVAL Self-Assertion conversion checkpoint — 2026-11-19

Source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`
Converter: `scap-ng-tools@f4a0df0361d199f66d582dc20a5eab1e1ba8ebdc`
Canonical schema: `scap-ng@5ee55288b369da26f308f40813e545b78dff2753` (`88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`)

## Summary

| Denominator | Converted | Blocked | Owner-excluded |
|---|---:|---:|---:|
| Definitions | 150 | 16 | 2 |
| Tests | 688 | 113 | 2 |

The current pinned corpus reconciles **168 Definitions and 803 Tests**. Older 167/785 figures are a narrower/stale denominator and are not substituted.

## Platform/family dispositions

| Family | Definitions (converted/blocked/excluded) | Tests (converted/blocked/excluded) |
|---|---:|---:|
| `agnostic` | 46/1/0 | 310/18/0 |
| `aix` | 0/0/2 | 0/0/2 |
| `asa` | 2/0/0 | 2/0/0 |
| `ios` | 10/1/0 | 12/4/0 |
| `iosxe` | 11/0/0 | 17/0/0 |
| `junos` | 1/1/0 | 1/1/0 |
| `linux` | 16/0/0 | 62/0/0 |
| `macos` | 17/3/0 | 34/9/0 |
| `panos` | 2/0/0 | 2/0/0 |
| `solaris` | 4/2/0 | 12/9/0 |
| `unix` | 12/1/0 | 60/12/0 |
| `windows` | 29/7/0 | 176/60/0 |

## Qualification boundary

- Native output passed the pinned SCAP-NG 0.4.1 schema gates for converted rows.
- No host collection or RI runtime execution was performed by this checkpoint.
- No expected outcomes were used as evaluator inputs.
- Independent OVAL equivalence is not proved.

The full machine ledgers remain external at the evidence root recorded in the JSON receipt; only compact hashes and source-linked blocker summaries are versioned here.
