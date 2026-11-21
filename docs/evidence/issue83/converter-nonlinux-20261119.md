# Current non-Linux source-to-native conversion — 2026-11-19

This receipt replays the remaining Self-Assertion platform families through the production converter at the exact flat SCAP-NG 0.4.1 schema. It is authoring evidence only; no runtime or independent OVAL equivalence is claimed.

## Pins

- Source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`.
- Converter: `vanderpol/scap-ng-tools@c97877027052cfe95cb8ad9a52f542da15b03366`, production `scap_ng_tools.converter.direct04`.
- Canonical schema: `vanderpol/scap-ng@5ee55288b369da26f308f40813e545b78dff2753`, SCAP-NG `0.4.1`, aggregate SHA-256 `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`.

## Results

| Family | Definitions | Converted | Blocked | Excluded | Tests | Converted | Blocked | Excluded |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| aix | 2 | 0 | 0 | 2 | 2 | 0 | 0 | 2 |
| asa | 2 | 2 | 0 | 0 | 2 | 2 | 0 | 0 |
| ios | 11 | 10 | 1 | 0 | 16 | 12 | 4 | 0 |
| iosxe | 11 | 11 | 0 | 0 | 17 | 17 | 0 | 0 |
| junos | 2 | 1 | 1 | 0 | 2 | 1 | 1 | 0 |
| macos | 20 | 17 | 3 | 0 | 43 | 34 | 9 | 0 |
| panos | 2 | 2 | 0 | 0 | 2 | 2 | 0 | 0 |
| solaris | 6 | 4 | 2 | 0 | 21 | 12 | 9 | 0 |
| **Total** | **56** | **47** | **7** | **2** | **105** | **80** | **23** | **2** |

All non-AIX generated native documents passed the independent schema/readback validation recorded in each external manifest. AIX is an explicit owner exclusion, not a conversion success.

## Exact blocked source records

| Family / source file | Definition/Test ID | Source XML SHA-256 | Class | Diagnostic |
|---|---|---|---|---|
| `ios/SCAP_1.4/OVAL_Test_Content/ios/ios-def_version55_test.xml` | `oval:navy.navwar.niwcatlantic.scc.ios:def:1`, `oval:navy.navwar.niwcatlantic.scc.ios:tst:1`, `oval:navy.navwar.niwcatlantic.scc.ios:tst:2`, `oval:navy.navwar.niwcatlantic.scc.ios:tst:3`, `oval:navy.navwar.niwcatlantic.scc.ios:tst:5` | `a7b8bd9f2b9bc375dfaedccdb34a991eb50d372aea7aceb942c8867e0ba9e897` | `unsupported` | unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#ios}version_test |
| `junos/SCAP_1.4/OVAL_Test_Content/junos/junos-def_xml_config_test.xml` | `oval:org.joval.junos.test:def:1`, `oval:org.joval.junos.test:tst:1` | `9e5f0a63627bc1a965aba6e7597af7ac677b3c186696fdd3fd4f5ac2f7c17cf5` | `unsupported` | unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#junos}xml_config_test |
| `macos/SCAP_1.4/OVAL_Test_Content/macos/ind-def_environmentvariable58_test_mac.xml` | `oval:navy.navwar.niwcatlantic.scc.test:def:1`, `oval:navy.navwar.niwcatlantic.scc.test:tst:1`, `oval:navy.navwar.niwcatlantic.scc.test:tst:2`, `oval:navy.navwar.niwcatlantic.scc.test:tst:3` | `aebed7527b5717f94755c28e37ee3357debaca7d3c024814f0b3c501e387ad16` | `converter_failure` | Variable cast outside bounded proof |
| `macos/SCAP_1.4/OVAL_Test_Content/macos/macos-def_keychain_test.xml` | `oval:org.joval.test:def:20002`, `oval:org.joval.test:tst:20002` | `53e1beb968074d18a1bade43e8d251a2387d44d19e12e76a720966ed5130a62b` | `unsupported` | unsupported object capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#independent}environmentvariable_object |
| `macos/SCAP_1.4/OVAL_Test_Content/macos/macos-def_nvram512_test.xml` | `oval:org.mitre.oval.test:def:448`, `oval:com.jovalcm.macos.inventory:tst:1000001600001`, `oval:org.joval.oval.test:tst:865`, `oval:org.mitre.oval.test:tst:308`, `oval:org.mitre.oval.test:tst:486`, `oval:org.mitre.oval.test:tst:865` | `de4dcd4ba3e81f63916db722c462aff48e1702f414b33879c4497d8421bd70cd` | `unsupported` | unsupported standalone source OVAL version: '5.10.1' |
| `solaris/SCAP_1.4/OVAL_Test_Content/solaris/sol-def_package511_test.xml` | `oval:navy.navwar.niwcatlantic.scc.test:def:1`, `oval:navy.navwar.niwcatlantic.scc.test:tst:1`, `oval:navy.navwar.niwcatlantic.scc.test:tst:2`, `oval:navy.navwar.niwcatlantic.scc.test:tst:3`, `oval:navy.navwar.niwcatlantic.scc.test:tst:4`, `oval:navy.navwar.niwcatlantic.scc.test:tst:5`, `oval:navy.navwar.niwcatlantic.scc.test:tst:6` | `02d6916a4e900126a83d86071587eccc024df9055a33b3b5dd7526d8cf542706` | `deprecated_source_construct` | deprecated source capability: package511_test (OVAL 5.12; OVAL 5.12.3 marks solaris:package511_test deprecated) |
| `solaris/SCAP_1.4/OVAL_Test_Content/solaris/sol-def_package_test.xml` | `oval:navy.navwar.niwcatlantic.scc.test:def:1`, `oval:navy.navwar.niwcatlantic.scc.test:tst:1`, `oval:navy.navwar.niwcatlantic.scc.test:tst:2`, `oval:navy.navwar.niwcatlantic.scc.test:tst:3` | `36c8be7fada857f6b1c191c780d58f9322a701f3c2f9c1b999c963b57eeed307` | `deprecated_source_construct` | deprecated source capability: package_test (OVAL 5.12; OVAL 5.12.3 marks solaris:package_test deprecated) |

The machine-readable JSON receipt contains one record per blocked Definition/Test and SHA-256/byte receipts for every retained family ledger. Raw outputs remain outside Git at `/tmp/issue83-converter-remaining-20261119.H0lSKK`.

## Qualification boundary

These are source-to-native authoring results. They do not qualify any non-Linux host, Windows/macOS/iOS/Solaris/network runtime, source OVAL equivalence, or complete authority. Deprecated constructs remain deprecated; source-invalid values and unsupported capabilities remain explicit holds.
