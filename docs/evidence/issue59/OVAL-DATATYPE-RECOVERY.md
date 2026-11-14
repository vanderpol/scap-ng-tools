# Standalone OVAL corpus datatype-recovery rebuild

This is a fresh production-CLI rebuild of the pinned OVAL Community SCAP Self-Assertion corpus, not a manual authoring set.

- Canonical schema commit: `aece827964c785be77b088c3c61255a2d07fd9a9`
- Schema digest: `578315d1e00bd39449ed597ed3d39555384276bd36198a54ca0b1e3c17e72829`
- OVAL source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`
- Scope: 144 files, 168 Definitions, 803 Tests; transitive `extend_definition` ownership retained.

## Exact disposition

| item | converted, unverified | blocked | owner-excluded | total |
|---|---:|---:|---:|---:|
| Definitions | 97 | 69 | 2 | 168 |
| Tests | 506 | 295 | 2 | 803 |

`execution=not_run`, `scanner_equivalent=false`, and `independent_source_equivalent=false`. Converted entries are schema-valid/source-traced only.

## Independent parity gate

Source accounting is complete, but the independent source-equivalence parity gate **fails**: 55 `converted_parity_failure` findings remain. They are preserved in the generated parity receipt and are not relabeled as conversion blockers or hidden. This is a failing RI/source-equivalence gate, not evidence for a scanner claim.

The machine-readable receipts, exact output hashes, blocker diagnostics, and parity status are in [`oval-accounting-datatype-recovery.json`](oval-accounting-datatype-recovery.json). The prior 92/478 corpus accounting remains unchanged in [`oval-accounting.json`](oval-accounting.json) as historical evidence.
