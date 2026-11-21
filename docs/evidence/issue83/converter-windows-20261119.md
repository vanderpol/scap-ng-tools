# Current Windows source-to-native conversion — 2026-11-19

This receipt replays the pinned Windows Self-Assertion source through the production converter and the exact flat SCAP-NG 0.4.1 schema. It is authoring/schema evidence only; runtime execution and independent OVAL equivalence were not run.

## Pins

- Source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa` (`SCAP_1.4/OVAL_Test_Content/windows`).
- Converter: `vanderpol/scap-ng-tools@c97877027052cfe95cb8ad9a52f542da15b03366`, production `scap_ng_tools.converter.direct04`.
- Canonical schema: `vanderpol/scap-ng@5ee55288b369da26f308f40813e545b78dff2753`, SCAP-NG `0.4.1`, aggregate SHA-256 `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`.

## Results

- Definitions: **36** (**29** converted, **7** blocked, 0 owner-excluded).
- Tests: **236** (**176** converted, **60** blocked, 0 owner-excluded).
- Schema-valid native YAML documents: **29**.
- Test ledger reconciliation: **complete**; identity is `(source_path, test_id, exact source XML SHA-256)`.
- Expected outcomes, collected Items and execution results: **not derived**.

### Blocker counts

| Class | Definitions | Tests |
|---|---:|---:|
| `deprecated_source_construct` | 1 | 1 |
| `source_typed_literal_invalid` | 2 | 8 |
| `schema_or_validation_failure` | 2 | 35 |
| `unsupported` | 1 | 7 |
| `converter_failure` | 1 | 9 |

## Exact blocked source identities

| Source file | Definition/Test IDs | Class | Diagnostic / disposition |
|---|---|---|---|
| `windows/win-def_auditeventpolicysubcategories_test.xml` (SHA-256 `ed2cb11222b6fc78e27696b91f87ecbd649757e3e38752c89a245d9099905363`) | `def:708`; `tst:768` | deprecated source construct | `kerberos_ticket_events` is deprecated; no SCAP-NG behavior added. |
| `windows/win-def_lockoutpolicy_test.xml` (SHA-256 `30818be7d856dde1975e451858029e8de8deeb53c370dc979581256995681ade`) | `def:705`; `tst:1268` | source typed literal invalid | Negative policy literal rejected as source-invalid; requires upstream correction. |
| `windows/win-def_ntuser_test.xml` (SHA-256 `0a99c404acffc27b2d22b37e8dde4b9a6a90497bb708ba995ae6c1fb90505e92`) | `def:38`; `tst:1,2,3,4,5,6,7,8,13,14,16,17,19,20,22,23,24,25,26,28` | schema/validation | Generated NTUSER traversal forms are not admitted by the pinned canonical schema. |
| `windows/win-def_passwordpolicy_test.xml` (SHA-256 `0e0fc39654d0f875b0ee1e1e29ee1a172a6dd4eec5cd81e0bdb4d67a10f4183f`) | `def:998`; `tst:10,20,30,40,50,60,70` | source typed literal invalid | Negative policy literals rejected as source-invalid; requires upstream correction. |
| `windows/win-def_registry_test.xml` (SHA-256 `c23ce82a7a02813e2f441ccf18080eeec621dd6af0d4ffaacbb32150b34fa3ec`) | `def:38`; `tst:1000,1010,1020,5020,1030,1040,1080,1090,1100,1110,3000,3010,4000,4010,4020` | schema/validation | Registry traversal forms are not admitted by the pinned canonical schema. |
| `windows/win-def_regkeyeffectiverights53_test.xml` (SHA-256 `979a31ad5cdcd249fb01340f3b4c0939eab825b7852c71636f222a00c7804219`) | `def:729`; `tst:664,1289,525,1006,680,1474,1141` | unsupported | `include_group` / `resolve_group` behavior has no approved native mapping. |
| `windows/win-def_wuaupdatesearcher_test.xml` (SHA-256 `e593f5c5c2b4ec09390ec8c8c2a907084714f79707a71b15e9880f532da2f26b`) | `def:1`; `tst:1,2,3,4,5,6,7,8,9` | converter failure | Variable cast is outside the converter's bounded typed proof. |

The machine-readable receipt contains all 60 blocked Test records and the exact external artifact hashes.

## Reproduction

```bash
# Use the pinned source checkout, schema snapshot, and converter commit above.
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  ./.venv/bin/python scripts/convert_self_assertion_corpus.py \
  --corpus <source-checkout> \
  --schema-root <schema-root> \
  --source-commit e3538595c5083b9c34d937a81d319234df9bbfaa \
  --output <output> --family windows
```

Raw generated ledgers remain outside Git at `/tmp/issue83-converter-windows-run.eL0yXL/results`; the JSON receipt records their SHA-256 and byte lengths.

## Qualification boundary

A converted/schema-valid document is not proof of Windows runtime support, source OVAL equivalence, or complete Windows host authority. Windows Registry/NTUSER traversal, group-resolution authority, policy source corrections and update Variable casting remain explicit holds.
