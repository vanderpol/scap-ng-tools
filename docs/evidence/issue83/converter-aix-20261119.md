# AIX source-to-native conversion — 2026-11-19

This is a focused rerun after removing the stale AIX owner-exclusion branch from `scripts/convert_self_assertion_corpus.py`. Owner scope now includes all nondeprecated OVAL platform families for authoring conversion. Runtime qualification remains separate.

## Pins

- Source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`.
- Converter: `vanderpol/scap-ng-tools@c613280`, production `scap_ng_tools.converter.direct04`.
- Canonical schema: `vanderpol/scap-ng@5ee55288b369da26f308f40813e545b78dff2753`, SCAP-NG `0.4.1`, aggregate SHA-256 `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`.

## Result

- **2 Definitions / 2 Tests**
- **2 Definitions / 2 Tests converted**
- **2 schema-valid native YAML documents**
- **0 blocked, 0 excluded**
- Source ledger reconciliation: complete.

Both `aix.fileset` and `aix.fix` mappings were exercised successfully. This proves authoring/schema admission only; it does not prove AIX host collection, evaluator behavior, or independent OVAL equivalence.

The previous receipt's AIX exclusion was a stale replay-harness policy, not a source or canonical language disposition. Exact source identities and external artifact hashes are in the machine-readable receipt.
