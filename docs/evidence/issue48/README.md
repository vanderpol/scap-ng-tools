# Issue #48 qualification evidence

This candidate restores explicit native SCAP-NG 0.4 Variable transformations
without changing Results, scope, or the immutable applicability.8/count.1
archives.

- Schema candidate: `vanderpol/scap-ng@63110e7762f4963d3e4d407e90b9fcfd9cfe86ad`
- Schema family SHA-256: `5d3b7f9507318c5ca2e85009fd8bc284d906d357b58cd278219c84f9481536a1`
- Source: `8c8e5dff860af6b1290ee9273a282db24278f8d5`
- Previous count.1: `6424 converted / 1403 manual / 163 blocked / 209 excluded`
- Target candidate disposition: `6474 converted / 1403 manual / 113 blocked / 209 excluded`

## Targeted qualification

`targeted/TARGETED-QUALIFICATION.json` converts the exact 55 Rule regressions
and all 37 count-bearing Rule instances independently, with the exact pinned
schema and native recovery path.

- 92 target instances (55 regression + 37 count; overlapping identities are
  intentionally run twice under their distinct qualification labels)
- 82 converted, 10 blocked
- Regressions: 50 recovered, 5 remain blocked by unrelated restrictions
- Count: 32 converted, 5 remain blocked by unrelated restrictions
- Schema validation passed for every admitted target

The remaining blockers are preserved with exact errors in the machine-readable
report. Structural qualification is not runtime/scanner equivalence.
