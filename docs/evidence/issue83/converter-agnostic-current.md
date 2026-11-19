# Current agnostic OVAL witness conversion

This is a complete agnostic-prefix source-witness conversion receipt using the
current Tools branch and exact flat schema preflight. It is authoring proof
only; it is not source expected-result proof, RI execution, or independent OVAL
equivalence.

- Source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`
- Converter: `a67f96e`
- Canonical schema: `5ee55288b369da26f308f40813e545b78dff2753`
- Schema family: `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`
- Witness receipt: `d4741fdae77705015bdbe060f5be8b35ea88cc01b7cf0062660fd7ddec32018e`
- Receipt: `/tmp/tools-issue83-current-conversion-agnostic-final-1795107293/receipt.json`
- Receipt SHA-256: `5973ca6e8db5aabbf97b2479321b744792846365c849f779fa6b0c3a5ceddc6b`

## Result

- 328 source Tests considered
- 308 converted
- 20 blocked
  - 18 canonical input-constraint holds: external Variables with
    `possible_restriction`
  - 2 source-invalid typed literals: `tst:3` and `tst:4` in
    `agnostic/oval-def_merge.xml` (authored `datatype="int"` with nonnumeric
    lexical values)

No blocker was relabeled as conversion success. The two malformed source
literals remain source-content defects, and the 18 external Variable cases
remain canonical/input-contract holds.
