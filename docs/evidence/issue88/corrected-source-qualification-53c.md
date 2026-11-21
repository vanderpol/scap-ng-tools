# Corrected Self-Assertion and 65-benchmark qualification

- Source: `53c18ea31a1976209572ec8b068e1a02be588456` (old baseline `e3538595c5083b9c34d937a81d319234df9bbfaa`)
- Tools converter: `d26acce`
- Canonical: `44991ed3753944e47c42d76f157b29448b256a34` / `ef009d2b6fb4596476b0dbbd219285409a875988da16ef2cb6acb49d14dbd260`

## Standalone corrected source

| Measure | Result |
|---|---:|
| direct XML files | 143 |
| Definitions | 167 (117 converted / 50 blocked) |
| Tests | 799 (678 converted / 121 blocked) |
| XSD | {'valid': 143} |
| Schematron | {'clean_files': 142, 'failed-assert': 15, 'files_with_reports': 1} |

The source ledger is complete, but converted rows are authoring/schema admission only. The one Schematron-invalid file is retained as an explicit source hold: `solaris/sol-def_package511_test.xml`, inconsistent variable/`var_ref` datatypes (15 reports across schema views).

## 65 signed benchmark corpus

| Measure | Result |
|---|---:|
| benchmarks | 65 |
| active Rules | 7990 |
| candidate | {'blocked': 95, 'converted': 6492, 'manual_only': 1403} |
| blocked categories | {'schema-semantic': 13, 'unsupported-capability': 78, 'unsupported-construct': 4} |
| blocked→converted | 13 |
| converted→blocked | 0 |
| nonregression | True |

Runtime RI execution and independent OVAL equivalence remain unproved. AIX is counted in standalone conversion but has no host qualification.

Full machine receipts:
- `full65-current-449.json`
- `corrected-source-platform-53c.json`
- `corrected-source-parity-53c.json`
- `corrected-source-validation-53c.json`

The complete generated Definition/Assessment package remains external at the command output path; hashes above make it reproducible without adding generated package contents to Git.
