# OVAL 5.12.3 schema-reference resolution

This is a source-first crosswalk increment for Issue #83. It does not claim
native support, conversion success, or runtime equivalence.

- OVAL schema commit: `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`
- Schema root: `oval-schemas/` (54 XSD files; manifest SHA is recorded by the
  generated inventory)
- Generator: `scripts/build_issue83_source_crosswalk.py::oval_inventory`
- Reproducible command: `SCAP_NG_OVAL_SCHEMA_ROOT=/path/to/oval-schemas
  python scripts/build_issue83_source_crosswalk.py ...` or call
  `oval_inventory` for schema-only output.
- External receipt: `/tmp/tools-issue83-semantics-final-1795106505/oval-schema-inheritance.json`
- Receipt SHA-256: `50f975d52e00ea99fadf4d5d26a939a829658b66f7309307ef3abd791f6fe06a`

## Measured result

The inventory covered 46 OVAL definition/system-characteristics schemas,
1,426 declarations, 42,567 grammar rows and 1,572 named local components.
It resolved 7,707 of 7,913 QName-bearing references. The remaining 206 are
built-in XML Schema references (for example `xsd:string`) and are classified
as `external_builtin`, not silently treated as local source components. No
unresolved external or unknown-prefix references remained in the pinned
schema set. All 79 declaration base references were either resolved locally
or explicitly identified as XML Schema built-ins; no declaration had
`schema_inheritance.status=incomplete`.

The report records direct local base targets and external built-in bases and
now emits 12,390 structural effective-member rows with origin, source path,
cardinality/default/use/type attributes and inherited/direct provenance. This
is an auditable field inventory, not semantic field merging or override
behavior. The same run records 1,599 extension/restriction rows and 4,447
facet rows as structural source evidence; restriction validity and override
semantics remain uninterpreted. The pinned schemas additionally contain
5,912 Schematron rows (982 assertions, 200 reports), 9,023 prose rows,
9 evaluation-documentation rows and 21 evaluation charts. These are retained
as source-linked semantic holds, not executed rules. Effective XSD
field/cardinality semantics, converter parity and RI execution remain separate
qualification work.
