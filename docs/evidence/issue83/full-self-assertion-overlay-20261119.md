# Self-Assertion source-correction overlay receipt

Source overlay commit: `7299504eb5c2356e85437b123e6b6ff8355325c9` (base `e3538595c5083b9c34d937a81d319234df9bbfaa`).  
Converter: `0311226e3f752f529d0a8ff1a3d337bb5a908590`; canonical schema: `5ee55288b369da26f308f40813e545b78dff2753`.

This is schema admission/conversion evidence only; execution and independent OVAL equivalence are not proved.

## Summary

| Record | Total | Converted | Blocked |
|---|---:|---:|---:|
| Definitions | 165 | 160 | 5 |
| Tests | 790 | 728 | 62 |

## Platform outcomes

| Platform | Definitions | Tests |
|---|---|---|
| agnostic | `{'CONVERTED_UNVERIFIED': 46, 'blocked': 1}` | `{'CONVERTED_UNVERIFIED': 310, 'blocked': 18}` |
| aix | `{'CONVERTED_UNVERIFIED': 2}` | `{'CONVERTED_UNVERIFIED': 2}` |
| asa | `{'CONVERTED_UNVERIFIED': 2}` | `{'CONVERTED_UNVERIFIED': 2}` |
| ios | `{'CONVERTED_UNVERIFIED': 10, 'blocked': 1}` | `{'CONVERTED_UNVERIFIED': 12, 'blocked': 4}` |
| iosxe | `{'CONVERTED_UNVERIFIED': 11}` | `{'CONVERTED_UNVERIFIED': 17}` |
| junos | `{'CONVERTED_UNVERIFIED': 1}` | `{'CONVERTED_UNVERIFIED': 1}` |
| linux | `{'CONVERTED_UNVERIFIED': 16}` | `{'CONVERTED_UNVERIFIED': 62}` |
| macos | `{'CONVERTED_UNVERIFIED': 20}` | `{'CONVERTED_UNVERIFIED': 43}` |
| panos | `{'CONVERTED_UNVERIFIED': 2}` | `{'CONVERTED_UNVERIFIED': 2}` |
| solaris | `{'CONVERTED_UNVERIFIED': 4}` | `{'CONVERTED_UNVERIFIED': 12}` |
| unix | `{'CONVERTED_UNVERIFIED': 13}` | `{'CONVERTED_UNVERIFIED': 71}` |
| windows | `{'CONVERTED_UNVERIFIED': 33, 'blocked': 3}` | `{'CONVERTED_UNVERIFIED': 194, 'blocked': 40}` |

## Remaining Definition blockers

| Definition | Class | Source |
|---|---|---|
| `oval:org.mitre.oval.test:def:562` | `canonical_input_constraint_hold` | `SCAP_1.4/OVAL_Test_Content/agnostic/oval-def-ext.zip!oval-def-ext.xml` |
| `oval:navy.navwar.niwcatlantic.scc.ios:def:1` | `canonical_capability_gap` | `SCAP_1.4/OVAL_Test_Content/ios/ios-def_version55_test.xml` |
| `oval:navy.navwar.niwcatlantic.scc.windows.test:def:38` | `canonical_traversal_schema_hold` | `SCAP_1.4/OVAL_Test_Content/windows/win-def_ntuser_test.xml` |
| `oval:org.mitre.oval.test:def:38` | `canonical_traversal_schema_hold` | `SCAP_1.4/OVAL_Test_Content/windows/win-def_registry_test.xml` |
| `oval:org.mitre.oval.test:def:729` | `canonical_traversal_schema_hold` | `SCAP_1.4/OVAL_Test_Content/windows/win-def_regkeyeffectiverights53_test.xml` |

## Holds

- External Variable/Input cases remain a canonical input-contract hold.
- iOS `version55_test` remains a canonical capability gap.
- Three Windows registry traversal families remain canonical schema holds.
- No runtime execution or independent OVAL equivalence is claimed.
