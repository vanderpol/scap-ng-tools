# Corrected Self-Assertion and 65-benchmark qualification

- Source: `53c18ea31a1976209572ec8b068e1a02be588456` (old baseline `e3538595c5083b9c34d937a81d319234df9bbfaa`)
- Tools converter: `01dedc4ac371e7388ea6a328e00d8e234a0ca449`
- Canonical: `44991ed3753944e47c42d76f157b29448b256a34` / `ef009d2b6fb4596476b0dbbd219285409a875988da16ef2cb6acb49d14dbd260`
- OVAL schema: `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706` (5.12.3)

## Standalone corrected source

| Measure | Result |
|---|---:|
| direct XML files | 143 |
| Definitions | 167 (161 converted / 6 blocked) |
| Tests | 799 (743 converted / 56 blocked) |
| AIX | 2/2 Definitions, 2/2 Tests structurally converted; runtime not qualified |
| XSD | 143/143 valid |
| Schematron | 142 clean; 1 file with 15 failed assertions |

The source ledger is complete. The Schematron hold is retained explicitly: `solaris/sol-def_package511_test.xml` contains inconsistent Variable/`var_ref` datatypes (15 reports across imported schema views). The four parity problems are three source-invalid Variable declarations (`def:895`, `def:38`, `def:580`) and one native collected-field datatype hold (`macos def:20002`). No source-invalid case is coerced.

## 65 signed benchmark corpus

| Measure | Result |
|---|---:|
| benchmarks | 65 |
| active Rules | 7,990 |
| candidate | 6,492 converted / 95 blocked / 1,403 manual-only |
| blocker categories | 78 unsupported-capability / 13 schema-semantic / 4 unsupported-construct |
| blocked→converted | 13 |
| converted→blocked | 0 |
| nonregression | PASS |

This is authoring/schema qualification, not scanner runtime proof. RI execution and independent OVAL equivalence remain unproved; wrong-platform and AIX runtime holds remain separate.

Machine receipts:

- `full65-current-449.json`
- `corrected-source-platform-53c.json`
- `corrected-source-parity-53c.json`
- `corrected-source-validation-53c.json`

The generated Definition/Assessment package remains external. The receipt records exact source, schema, converter and ledger hashes for reproducibility without committing the large package.
