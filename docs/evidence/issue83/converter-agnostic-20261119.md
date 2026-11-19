# Current agnostic source-to-native conversion — 2026-11-19

This receipt is the current production-converter replay of the pinned agnostic Self-Assertion content, including `oval-def-ext.zip!oval-def-ext.xml`. It is authoring/schema evidence only; runtime execution and independent OVAL equivalence were not run.

## Pins

- Source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`
- Converter/Tools: `5eca912fb76fef1a999a6a9f8734fda47e511a77`
- Canonical: `vanderpol/scap-ng@5ee55288b369da26f308f40813e545b78dff2753`
- Flat schema family: `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`
- Assessment execution family: `326f82668020a717f5d3443484330f313146978292befd75c063f55b2e4e5329`

## Results

- Definitions: **47**
- Tests: **328** (including 18 archive-member Tests)
- Converted Definitions: **46**
- Converted Tests: **310**
- Schema-valid native YAML documents: **46**
- Blocked Definition: **1**
- Blocked Tests: **18**
- Execution: not run

All 18 blocked Tests belong to `def:562` and retain the same explicit `canonical_input_constraint_hold`: `unbound external Variable or unsupported possible_restriction`. The converter did not bind external values, use OpenSCAP outcomes, or fabricate native semantics. This is the expected separation between source execution evidence and converter admissibility.

Raw conversion artifacts remain external under the recorded `/tmp` root. The compact JSON receipt preserves exact artifact hashes and the full blocked ID list.
