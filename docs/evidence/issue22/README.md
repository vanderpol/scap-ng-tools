# Issue #22 benchmark golden-parity audit

This directory records a read-only comparison of the pinned Q3 2026 benchmark
fixtures using the historical converter/schema pair (`scap-ng-tools` `1f4f74d`
+ `scap-ng` `354c9c9`) and the Candidate-A output after the accepted
`filepath`/`path`/`filename` correction.

- `benchmark-difference-report.json` is the machine-readable report.
- `*-before.yaml` and `*-after.yaml` are representative canonical Assessment
  pairs. Historical goldens and source ZIPs are not changed.

## Result

All four fixtures retain the same source Rule IDs, inventory counts, converted
counts, blocked counts, capability coverage, and source provenance. The 11
historical parity assertions are representation/provenance assertions:

- 2 native-document digests: Amazon Linux and Windows Server filesystem field
  names changed from `full_path`/`directory` to canonical `filepath`/`path`.
- 4 automatic trace digests and 4 inventory trace digests: first difference is
  `/mapping_sha256/unix.file`, reflecting the approved mapping correction.
- 1 CLI common-byte digest: the same filesystem selector representation change.

A temporary run initially lost six Windows Rules because generated capability
objects used `additionalProperties: false` without exposing the already-defined
OVAL Set form or NTUSER collection parameters. The schema correction exposes
`set`, `include_default`, and `item_creation`; the converter then returns the
historical 496 documents / 247 converted / 44 blocked. No language or converter
semantic behavior was invented or changed.

## Inventory 0 explanation

The inventory test asserted each historical trace hash before incrementing its
aggregate counter. Since all four traces differ only at the approved mapping
hash, execution reached no increment and printed `0 != 535`. The test now counts
`source_rules` immediately after validating the source count; it still asserts
the unchanged historical hashes and therefore still fails until an owner-approved
migration is merged.

## Verification

Focused schema tests pass (10 tests), including native Set operands, NTUSER
collection parameters, positive/negative selector constraints, and YAML
round-trips. The four-fixture candidate conversion produced 535 inventory
records and 766 native documents with 380 converted / 155 blocked Rules. The
historical parity suite remains intentionally failing; no golden was modified.
