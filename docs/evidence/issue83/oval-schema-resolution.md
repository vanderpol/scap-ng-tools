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
- External receipt: `/tmp/tools-issue83-inheritance-final3-1795106291/oval-schema-inheritance.json`
- Receipt SHA-256: `796c0b3fad7af5c954398e1d5a2424ac8ef1a39f60fb7fa571c4b174bf7cc964`

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

The report records direct local base targets and external built-in bases but
does not flatten inherited fields. Effective inherited field/cardinality
semantics, Schematron/prose constraints, converter parity and RI execution
remain separate qualification work.
