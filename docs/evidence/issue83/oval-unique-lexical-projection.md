# OVAL `unique` lexical projection

Source pin: OVAL-Community/OVAL 5.12.3 at
`2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`. The exact source XSD is
`oval-schemas/oval-definitions-schema.xsd`, SHA-256
`06b79e8683d6b9dcaad3ab074a456588ed82c4edd2e8fff209def10aa0a366cc`.
`UniqueFunctionType` (lines 933–940) says every component is treated as a
string and collection values participate in duplicate removal.

The source-to-native adapter now expresses this boundary as
`concat(literal(""), operand)` for **every** source operand, including typed
literals and Variable references. This is an explicit one-to-one lexical
projection; it does not deduplicate, reorder, or drop values during conversion.
Record operands remain a fail-closed native typing error. Existing authored
SCAP-NG `unique` expressions are not rewritten.

Focused proof:

- integer `1` plus string `"1"` lowers to two lexical operands and validates as
  a string result; runtime duplicate removal is not claimed;
- a record operand is rejected by scalar text typing;
- all source order/cardinality and provenance checks pass.

The machine-readable source evidence, adapter paths, and holds are in
[`oval-unique-lexical-projection.json`](oval-unique-lexical-projection.json).
This is converter/source admission proof only, not OVAL or RI runtime
independent equivalence.
