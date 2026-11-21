# Full current converter structural parity — 2026-11-19

This receipt runs the independent source-to-native parity auditor against a clean full-corpus production conversion after the AIX scope correction. It does not execute the RI or prove OVAL runtime equivalence.

## Pins and package

- Source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`; 144 XML files, 168 Definitions, 803 Tests.
- Conversion: Tools `c613280` production package; parity auditor current head `33c1c08`, `scap_ng_tools.converter.direct04`.
- Canonical schema: SCAP-NG `0.4.1`, `vanderpol/scap-ng@5ee55288b369da26f308f40813e545b78dff2753`, aggregate SHA-256 `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`.

## Result

- Source ledger: **fully accounted** — 0 undispositioned Definitions and 0 undispositioned Tests.
- Native authoring: **152 Definitions / 690 Tests** schema-valid; 16 Definitions / 113 Tests remain explicit converter/source holds.
- Independent structural parity: **144 Definitions / 658 source-mapped Tests checked**.
- Structural parity failures among source-valid converted Definitions: **0**.
- Source-invalid compatibility conversions exposed by parity: **8 Definitions**.
- Runtime/independent OVAL equivalence: **not proved**.

## Source-invalid cases exposed

The eight cases are all agnostic Variable datatype declarations that do not agree with their expression result or are normalized by the compatibility adapter: `def:895` (`var:589`), `def:67` (`var:524`, `var:712`), `def:620`, `def:997`, `def:117`, and `def:97` (`var:945`), `def:38` in `oval-def_merge.xml` (`var:1`, `var:101`, `var:2`, `var:3`, `var:4`), and `def:580` (`var:561`, time_difference declared as string although the function returns integer). These remain source-content holds, not converter successes. The JSON receipt now retains exact source XML hashes, affected Test IDs, Variable declaration/result types, source-node hashes and any compatibility normalization for each case.

The audit also corrected false parity failures for canonical field-level quantifier projection, finite Variable Object Set expansion, expanded Boolean/negation groups, inherited literal datatypes, and active `time_difference` result typing.

Raw package and audit output remain external; the machine receipt records SHA-256 values and exact source-linked diagnostics.
