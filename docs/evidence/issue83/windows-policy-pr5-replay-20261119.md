# Windows policy content correction replay — PR #5

This focused replay uses the proposed Self-Assertion content correction from PR #5, not the pinned baseline. It does not change the pinned source or claim Windows runtime equivalence.

- Baseline source: `e3538595c5083b9c34d937a81d319234df9bbfaa`
- Correction branch: `cc3be23f51913561c96aacaf36f4838a78100cdf`
- Converter: Tools `c6132809220f4214ba5b4842797a2b7fd0125df8`
- Canonical schema: `5ee55288b369da26f308f40813e545b78dff2753`

| Definition | Original status | Corrected status | Tests |
|---|---|---|---:|
| `def:705` lockout policy | blocked: source typed literal | `CONVERTED_UNVERIFIED`, schema-valid | 1 |
| `def:998` password policy | blocked: source typed literal | `CONVERTED_UNVERIFIED`, schema-valid | 7 |

The proposed corrections replace invalid negative lower bounds with `0`. Native conversion succeeds for both Definitions. Full source IDs, exact XML hashes, native artifact hashes, and limitations are in the JSON receipt.
