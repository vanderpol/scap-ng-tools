# Current Windows OVAL witness conversion (diagnostic)

This is source-witness authoring qualification only. It does not claim Windows
runtime support or source-equivalence.

- Source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`
- Converter: `6178ad8`
- Canonical schema: `5ee55288b369da26f308f40813e545b78dff2753`
- Schema family: `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`
- Receipt: `/tmp/tools-issue83-current-conversion-windows-final-1795108225/receipt.json`
- SHA-256: `beb38a47e138a426361386fab952cd78198a17835c1b48da45c9dac70943dbcf`

## Result

- 218 Tests considered
- 203 converted
- 15 blocked
  - 8 canonical schema validation failures for emitted Registry/NTUSER/
    RegKeyEffectiveRights `traversal` shapes
  - 5 unsupported source constructs: Object `notes`, audit-event State field,
    and `include_group`/`resolve_group`
  - 2 source policy-invalid negative literals

The eight traversal failures remain a canonical schema-contract hold; fields
were not dropped to manufacture conversion success. The two negative literals
remain source-invalid. Windows host/runtime qualification is not inferred.
