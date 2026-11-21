# Issue #83 compact source audit

This compact receipt is derived from an external full source crosswalk. It is a source-language and conversion-gap audit, not runtime or independent equivalence proof.

- Source archives/Rules: **65 / 8892**
- Source archive-set SHA-256: `6e04353f3b1ef32b31a6ef022f75cd7c68486dadb017bd18aa9108c3864ed1ca`
- Full crosswalk SHA-256: `fefc748e283ad07b0b4aea1ac5843377073bd3e40132eaaf4e08085c734e31c7` (109092502 bytes)
- OVAL schema: `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`
- Canonical 0.4.1: `5ee55288b369da26f308f40813e545b78dff2753`; schema family `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`
- Converter audit head: `119455c8bc2cdf462ba87be396bb822f48b9e14c`

## Reproduction

Use the exact pinned 65-archive source directory without copying it into the repository. The full crosswalk is intentionally external; its byte hash is recorded above.

```sh
python3 scripts/build_issue83_source_crosswalk.py \
  --source-root "$SCAP_NG_FULL65_SOURCE_ROOT" \
  --source-commit 8c8e5dff860af6b1290ee9273a282db24278f8d5 \
  --oval-schema-root "$OVAL_5_12_3_SCHEMA_ROOT" \
  --canonical-mapping-root "$SCAP_NG_041_ROOT/schema/capability-mappings" \
  --canonical-mapping-commit 5ee55288b369da26f308f40813e545b78dff2753 \
  --output-json /tmp/issue83-crosswalk.json --output-md /tmp/issue83-crosswalk.md
python3 scripts/build_issue83_audit_receipt.py \
  --crosswalk-json /tmp/issue83-crosswalk.json \
  --candidate-receipt docs/evidence/issue83/full-self-assertion-conversion-20261119-candidate-all-fixes.json \
  --converter-commit 1add34c \
  --canonical-commit 5ee55288b369da26f308f40813e545b78dff2753 \
  --canonical-schema-sha256 88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f \
  --oval-commit 2f140ee5c5dd1ed9606fcd5afc301f6baeb48706 \
  --output-json docs/evidence/issue83/source-audit-20261119.json \
  --output-md docs/evidence/issue83/source-audit-20261119.md
```

## Measured XCCDF source coverage

- Rule requires/conflicts: **0** (requires 0, conflicts 0)
- Group relationships: **0** (requires 0, conflicts 0)
- Standard metadata elements: `{"fix": 8892, "fixtext": 8892, "ident": 21661, "reference": 8892}`
- DISA extended fields are present on `8867` Rules; only `VulnDiscussion` text is currently retained in the native Rule mapping.
- Publisher-looking malformed descriptions: **25**, classified as `{"source_embedded_publisher_payload_malformed": 25}`; source IDs/hashes and parse locations are retained in JSON without source bodies.

## OVAL schema inventory

- Declarations/grammar rows: **1426 / 42567**; canonical mapping rows **391**.
- Exact canonical mapping joins: **379**; unmatched mapping rows: **12** (`{"mapping_source_version_out_of_scope": 12}`).
- Official deprecation annotations: **374**; unproven declarations: **1189**.
- Schematron assertions/reports and prose rows: **982 / 200 / 9023**.

## Ranked reusable gap inventory

1. **P0 — shared_source_semantics** (inventory_only)
   - Measured: `{"evaluation_prose_rows": 9023, "schematron_assertions": 982, "schematron_reports": 200}`
   - Action: Build generic source-valid semantic witnesses and review converter/RI obligations before claiming parity.
2. **P0 — xccdf_rule_metadata** (canonical_contract_hold)
   - Measured: `{"fix": 8892, "fixtext": 8892, "ident": 21661, "reference": 8892}`
   - Action: Coordinate a lossless native mapping for ident/reference/fix/fixtext and DISA publisher fields; do not overload discussion or invent extensions.
3. **P1 — oval_shared_grammar** (source_crosswalk_incomplete_with_out_of_scope_mappings)
   - Measured: `{"canonical_mapping_rows": 391, "declarations": 1426, "exact_mapping_join_rows": 379, "grammar_rows": 42567, "grammar_rows_with_mapping": 379, "unmatched_mapping_reasons": {"mapping_source_version_out_of_scope": 12}, "unmatched_mapping_rows": 12, "unproven_declarations": 1189}`
   - Action: Complete field/attribute/default/cardinality/function dispositions from pinned XSD, Schematron and prose; keep the 12 explicitly OVAL 6.0 experimental mappings outside the OVAL 5.12.3 coverage denominator.
4. **P1 — platform_specific_schema_or_source_holds** (source_linked_holds)
   - Measured: `{"candidate_execution": "candidate overlay only; not merged source baseline", "candidate_hold_rows": 12}`
   - Action: Resolve only through shared canonical/converter contracts: external Variable/Input constraints, valid Windows traversal, and remaining iOS/Junos capabilities; preserve deprecated/source-invalid cases separately.
5. **P2 — group_relationships** (canonical_non_flattening_mapping_hold)
   - Measured: `{"source_group_conflicts": 0, "source_group_requires": 0, "source_groups_with_relationships": 0}`
   - Action: Retain fail-closed behavior and add a source-valid group witness when canonical mapping is approved.

## Candidate Self-Assertion qualification

- Summary: `{"blocked_definitions": 6, "blocked_tests": 63, "converted_definitions": 158, "converted_tests": 726, "definitions": 166, "excluded_definitions": 2, "excluded_tests": 2, "execution": "not_run", "schema_valid_yaml_documents": 158, "test_ledger_reconciled": 791, "tests": 791}`
- Execution: **candidate overlay only; not merged source baseline**; independent equivalence: **not_proved**.
- Source-linked hold records: **12**.

## Holds

- The native contract for standard XCCDF remediation/identification metadata and structured DISA publisher metadata is not changed by this audit; canonical coordination is required.
- Valid Windows downward traversal is a canonical schema hold, not a converter workaround. Deprecated source constructs stay separate and are not reintroduced.
- No schema-valid conversion count in this receipt is a claim of scanner execution or source-equivalence.
