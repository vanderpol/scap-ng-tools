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
- Receipt SHA-256: `c0fd54871fb6b0828efa6bed5d8fb612a9661d58cbf0d72eb4b488a2ceb2a326`

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
behavior. Effective XSD field/cardinality semantics, Schematron/prose
constraints, converter parity and RI execution remain separate qualification
work.
