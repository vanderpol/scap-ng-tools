# Self-Assertion source pin delta

- Old source: `e3538595c5083b9c34d937a81d319234df9bbfaa`
- Corrected source: `53c18ea31a1976209572ec8b068e1a02be588456`
- Scope: `SCAP_1.4/OVAL_Test_Content/`

This is source accounting only. Removed or corrected content is not converter recovery.

| Measure | Old | New | Delta |
|---|---:|---:|---:|
| content files (XML/archives) | 147 | 146 | -1 |
| direct XML files | 144 | 143 | -1 |
| Definitions | 168 | 167 | -1 |
| Tests | 803 | 799 | -4 |
| changed files | — | 91 | — |

## Removed source identities

- Definition `oval:org.joval.junos.test:def:1` in `SCAP_1.4/OVAL_Test_Content/junos/junos-def_xml_config_test.xml`
- Test `oval:org.joval.junos.test:tst:1` in `SCAP_1.4/OVAL_Test_Content/junos/junos-def_xml_config_test.xml`
- Test `oval:org.mitre.oval.test:tst:466` in `SCAP_1.4/OVAL_Test_Content/unix/ind-def_textfilecontent54_test_unix.xml`
- Test `oval:org.mitre.oval.test:tst:1141` in `SCAP_1.4/OVAL_Test_Content/windows/win-def_regkeyeffectiverights53_test.xml`
- Test `oval:org.mitre.oval.test:tst:1474` in `SCAP_1.4/OVAL_Test_Content/windows/win-def_regkeyeffectiverights53_test.xml`

## Disposition

- `source_fixed_or_updated`: changed source bytes require a separate corrected-source qualification.
- `deprecated_or_invalid_content_removed`: removed source identities remain excluded from the new denominator.
- `converter_recovery`: 0; no converter result is inferred from the delta.
- RI execution and independent OVAL equivalence: not run by this receipt.
