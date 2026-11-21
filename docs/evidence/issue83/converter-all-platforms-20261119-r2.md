# Complete all-platform source-to-native conversion — 2026-11-19 (AIX correction)

This supersedes [`converter-all-platforms-20261119`](converter-all-platforms-20261119.md). The replay harness no longer applies the stale AIX owner exclusion. All pinned OVAL platform families are authoring targets; unsupported or schema-held content remains explicitly blocked.

## Pins

- Source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`.
- Canonical schema: `vanderpol/scap-ng@5ee55288b369da26f308f40813e545b78dff2753`, SCAP-NG `0.4.1`, aggregate SHA-256 `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`.
- Current harness: `vanderpol/scap-ng-tools@c613280`.

## Current complete denominator

| Cohort | Definitions | Converted | Blocked | Excluded | Tests | Converted | Blocked | Excluded |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| agnostic | 47 | 46 | 1 | 0 | 328 | 310 | 18 | 0 |
| Linux + UNIX | 29 | 28 | 1 | 0 | 134 | 122 | 12 | 0 |
| Windows | 36 | 29 | 7 | 0 | 236 | 176 | 60 | 0 |
| remaining non-AIX families | 54 | 45 | 7 | 0 | 103 | 80 | 23 | 0 |
| AIX | 2 | 2 | 0 | 0 | 2 | 2 | 0 | 0 |
| **Total** | **168** | **152** | **16** | **0** | **803** | **690** | **113** | **0** |

### Before → after

- Converted: **150 → 152 Definitions**, **688 → 690 Tests**.
- Excluded: **2 → 0 Definitions**, **2 → 0 Tests**.
- Newly qualified authoring capabilities: `aix.fileset` and `aix.fix`.

The 803-Test denominator includes all XML Tests and helper/unowned Tests. The historical 785-Test figure used a different denominator and is not directly comparable.

## Qualification boundary

“Converted” means production native output passed canonical schema and JSON/YAML readback validation. It does not prove AIX runtime collection, evaluator behavior, or independent OVAL equivalence. Exact source identities and output hashes are in [`converter-aix-20261119.json`](converter-aix-20261119.json); prior cohort receipts retain all other source-linked blocker records.

Remaining blockers are canonical input constraints, deprecated/source-invalid content, canonical traversal gaps, unsupported platform capabilities and bounded converter cases. No source values were changed and no deprecated behavior was introduced.
