# Complete all-platform source-to-native conversion — 2026-11-19

This is a fresh joined ledger of the current source-pinned Self-Assertion conversion receipts. It is authoring/schema evidence only: no expected outcomes, runtime execution, host qualification or independent OVAL equivalence is claimed.

## Exact pins

- Source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`.
- Canonical schema: `vanderpol/scap-ng@5ee55288b369da26f308f40813e545b78dff2753`, SCAP-NG `0.4.1`, aggregate SHA-256 `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`.
- Converter entrypoint: `scap_ng_tools.converter.direct04`. Agnostic/Linux/UNIX replay receipt pin: `5eca912fb76fef1a999a6a9f8734fda47e511a77`; Windows/remaining-platform replay receipt pin: `c97877027052cfe95cb8ad9a52f542da15b03366`. Between those commits only qualification evidence was added; no converter implementation files changed.

## Complete source denominator

| Cohort | Definitions | Converted | Blocked | Excluded | Tests | Converted | Blocked | Excluded |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| agnostic | 47 | 46 | 1 | 0 | 328 | 310 | 18 | 0 |
| linux + unix | 29 | 28 | 1 | 0 | 134 | 122 | 12 | 0 |
| windows | 36 | 29 | 7 | 0 | 236 | 176 | 60 | 0 |
| remaining families | 56 | 47 | 7 | 2 | 105 | 80 | 23 | 2 |
| **Total** | **168** | **150** | **16** | **2** | **803** | **688** | **113** | **2** |

The complete current source inventory is **803 Tests / 168 Definitions**, including all XML Tests and helper/unowned Tests. The prior 785-Test status used a different denominator and must not be used for direct before/after comparisons.

## Meaning of the counts

- **Converted (688 Tests / 150 Definitions):** production converter emitted native artifacts that passed the pinned schema/readback gate. This does not prove evaluator or source equivalence.
- **Blocked (113 Tests / 16 Definitions):** a source, deprecated-construct, canonical-schema, unsupported-capability or bounded-converter hold preserved in the ledgers.
- **Excluded (2 Tests / 2 Definitions):** explicit AIX policy exclusion, not conversion success.

Exact blocked source IDs, source XML hashes and diagnostics are in the cohort receipts: [`agnostic`](converter-agnostic-20261119.json), [`Linux/UNIX`](converter-linux-unix-20261119.json), [`Windows`](converter-windows-20261119.json), and [`remaining platforms`](converter-nonlinux-20261119.json). The machine-readable joined receipt is [`converter-all-platforms-20261119.json`](converter-all-platforms-20261119.json).

## Remaining work

1. Resolve canonical external Variable/input constraints without changing source cardinality or expected-result semantics.
2. Keep deprecated upward recursion and deprecated platform constructs as source-content holds; do not add deprecated SCAP-NG behavior.
3. Coordinate canonical schema work for valid Windows traversal representations before changing Tools.
4. Implement only generic, bounded converter semantics for remaining Variable casts and supported platform capabilities; then rerun the affected source cohorts.
5. Runtime and independent OVAL equivalence remain separate qualification phases.
