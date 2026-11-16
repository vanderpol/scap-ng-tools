# Issue #69: exact 98 blocker groups (v2 exact-head receipt)

Receipt: `full65-operation-directed-v2-source-rule-rebuild.json`; SHA-256 `c6322a572f994d9ae0b65936c4e04e7940a49f4db8347a0bb72e426f3eab9e2b`.
Candidate: 6489 converted / 98 blocked / 1403 manual-only. Canonical schema `aece827964c785be77b088c3c61255a2d07fd9a9`; digest `578315d1e00bd39449ed597ed3d39555384276bd36198a54ca0b1e3c17e72829`. Historical converted→blocked gate: **PASS** (0 new regressions).

## canonical-capability-absent — 71

71 Rules use Windows OVAL `accesstoken_test` (66) or `user_test` (5). No corresponding canonical 0.4.1 capability mapping exists; no equivalent was fabricated.

- `xccdf_mil.disa.stig_rule_SV-220952r1051038_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}user_test
- `xccdf_mil.disa.stig_rule_SV-220956r958726_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220957r1137691_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220958r958726_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220959r1137691_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220960r958726_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220961r958726_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220962r958726_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220963r958726_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220964r958726_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220965r958726_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220966r958726_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220967r958726_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220968r1137691_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220969r1137691_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220970r1137691_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220971r1137691_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220972r1137691_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220973r958726_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220974r958726_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220975r1138519_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220976r958726_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220977r958726_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220978r958434_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220979r958726_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220980r958726_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220981r958726_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220982r958726_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-220983r958726_rule` — `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-253476r1210304_rule` — `U_MS_Windows_11_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}user_test
- `xccdf_mil.disa.stig_rule_SV-224997r958472_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-224998r958726_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-224999r958472_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225000r958472_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225001r958472_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225002r958472_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225003r958472_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225004r958672_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225005r958726_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225014r958472_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225015r958472_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225016r958472_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225017r958472_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225018r958472_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225019r958672_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225020r958726_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225070r958726_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225071r958726_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225072r958472_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225073r958726_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225074r958726_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225076r958726_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225077r958726_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225078r958726_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225079r958726_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225080r958726_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225081r958726_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225082r958726_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225083r958726_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225084r958726_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225085r958726_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225086r958434_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225087r958726_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225088r958726_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225089r958726_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225091r958726_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225092r958726_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-225093r958726_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test
- `xccdf_mil.disa.stig_rule_SV-205657r1153431_rule` — `U_MS_Windows_Server_2019_V3R9_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}user_test
- `xccdf_mil.disa.stig_rule_SV-254239r1153440_rule` — `U_MS_Windows_Server_2022_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}user_test
- `xccdf_mil.disa.stig_rule_SV-277986r1182007_rule` — `U_MS_Windows_Server_2025_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` — unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}user_test

## canonical-registry-traversal-gap — 1

1 Rule uses registry-object `traversal: max_depth=unlimited`, which the active registry mapping/schema does not express. Dropping traversal would weaken selection semantics.

- `xccdf_mil.disa.fso_rule_SV-225223r961038_rule` — `U_MS_DotNet_Framework_4-0_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV15-signed.zip` — authoring/direct-slice/assessments/digital-signatures-assemblies-verified-sv-225223-assessment.json: {'hive': {'equals': 'local_machine'}, 'key': {'equals': 'SOFTWARE\\Microsoft\\StrongName\\Verification'}, 'name': {'matches_regex': '.*'}, 'traversal': {'max_depth': 'unlimited'}} is not valid under any of the given schemas

## source-consumer-datatype-conflict — 1

1 Rule has a source consumer datatype that conflicts with the collected capability contract. No cast or datatype override is justified.

- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218771r1192784_rule` — `U_MS_IIS_10-0_Site_V2R14_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — authoring/direct-slice/assessments/iis-10-0-website-have-application-pool-sv-218771-assessment.json: Native comparison datatype: /tests/the-iis-10-0-website-must-have-a-unique-application-pool-test/require/fields/value: operand/explicit datatype conflicts with capability contract

## source-test-state-family-conflict — 7

7 Rules have source Test tags and referenced State/Object namespaces from different OVAL families (variable/appcmd/shellcommand). Reinterpreting the family would change source semantics.

- `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278400r1172752_rule` — `U_F5_NGINX_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` — state capability mismatch: oval:navy.navwar.niwcatlantic.scc.nginx:ste:27840004
- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218741r1022677_rule` — `U_MS_IIS_10-0_Site_V2R14_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.10.site:ste:21874102
- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218742r1022679_rule` — `U_MS_IIS_10-0_Site_V2R14_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.10.site:ste:21874205
- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218781r1022700_rule` — `U_MS_IIS_10-0_Site_V2R14_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.10.site:ste:21878101
- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214451r879567_rule` — `U_MS_IIS_8-5_Site_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` — state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.8.5.site:ste:80
- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214452r879568_rule` — `U_MS_IIS_8-5_Site_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` — state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.8.5.site:ste:93
- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214495r879587_rule` — `U_MS_IIS_8-5_Site_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` — state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.8.5.site:ste:180

## text-function-non_scalar_or_record_input — 12

12 Rules send a WMI query `result` record or another non-scalar lineage into source textual functions (`concat`/`end`). Records cannot be flattened without a source/runtime contract.

- `xccdf_mil.disa.fso_rule_SV-225230r1117185_rule` — `U_MS_DotNet_Framework_4-0_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV15-signed.zip` — authoring/direct-slice/assessments/net-clr-use-fips-approved-modules-sv-225230-assessment.json: Native comparison datatype: concat requires a scalar text operand
- `xccdf_mil.disa.fso_rule_SV-225232r1050651_rule` — `U_MS_DotNet_Framework_4-0_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV15-signed.zip` — authoring/direct-slice/assessments/net-applications-that-of-net-stig-guidance-sv-225232-assessment.json: Native comparison datatype: concat requires a scalar text operand
- `xccdf_mil.disa.fso_rule_SV-225234r1188289_rule` — `U_MS_DotNet_Framework_4-0_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV15-signed.zip` — authoring/direct-slice/assessments/net-default-proxy-reviewed-and-approved-sv-225234-assessment.json: Native comparison datatype: concat requires a scalar text operand
- `xccdf_mil.disa.fso_rule_SV-225235r960891_rule` — `U_MS_DotNet_Framework_4-0_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV15-signed.zip` — authoring/direct-slice/assessments/event-tracing-for-windows-events-enabled-sv-225235-assessment.json: Native comparison datatype: concat requires a scalar text operand
- `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-259637r961608_rule` — `U_MS_Exchange_2019_Edge_Server_V2R2_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` — authoring/direct-slice/assessments/exchange-software-partition-from-os-sv-259637-assessment.json: Native comparison datatype: concat requires a scalar text operand
- `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-259704r961608_rule` — `U_MS_Exchange_2019_Mailbox_Server_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` — authoring/direct-slice/assessments/exchange-email-with-another-application-sv-259704-assessment.json: Native comparison datatype: concat requires a scalar text operand
- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218795r960963_rule` — `U_MS_IIS_10-0_Server_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` — authoring/direct-slice/assessments/all-iis-10-0-web-server-iis-10-0-server-sv-218795-assessment.json: Native comparison datatype: concat requires a scalar text operand
- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214416r879627_rule` — `U_MS_IIS_8-5_Server_V2R7_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` — authoring/direct-slice/assessments/java-software-installed-virtual-machine-sv-214416-assessment.json: Native comparison datatype: concat requires a scalar text operand
- `xccdf_mil.disa.stig_rule_SV-224975r958524_rule` — `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — authoring/direct-slice/assessments/data-files-owned-by-users-data-files-sv-224975-assessment.json: Native comparison datatype: concat requires a scalar text operand
- `xccdf_mil.disa.stig_rule_SV-205723r1137695_rule` — `U_MS_Windows_Server_2019_V3R9_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — authoring/direct-slice/assessments/windows-server-2019-data-server-data-files-sv-205723-assessment.json: Native comparison datatype: concat requires a scalar text operand
- `xccdf_mil.disa.stig_rule_SV-254396r1137695_rule` — `U_MS_Windows_Server_2022_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — authoring/direct-slice/assessments/windows-server-2022-data-server-data-files-sv-254396-assessment.json: Native comparison datatype: concat requires a scalar text operand
- `xccdf_mil.disa.stig_rule_SV-278143r1182092_rule` — `U_MS_Windows_Server_2025_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` — authoring/direct-slice/assessments/windows-server-2025-data-server-data-files-sv-278143-assessment.json: Native comparison datatype: concat requires a scalar text operand

## unsupported-input-function-composition — 1

1 Rule composes an Assessment Input through an unsupported source function shape.

- `xccdf_mil.disa.stig_rule_SV-221718r991590_rule` — `U_Oracle_Linux_7_V3R3_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip` — Assessment Input function composition requires a supported typed expression

## unsupported-state-field-namespace — 2

2 Rules use State fields/namespaces not covered by the selected canonical capability mapping.

- `xccdf_mil.disa.stig_rule_SV-221653r1015161_rule` — `U_Oracle_Linux_7_V3R3_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip` — unsupported State field/namespace
- `xccdf_mil.disa.stig_rule_SV-214799r991589_rule` — `U_RHEL_7_V3R15_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — unsupported State field/namespace

## unsupported-variable-cast — 1

1 Rule uses a source Variable cast outside the bounded conversion proof.

- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218814r1067589_rule` — `U_MS_IIS_10-0_Server_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` — Variable cast outside bounded proof

## variable-source-set-filter-shape — 2

2 Rules use Sets/Filters inside a Variable source Object; the current native variable source grammar has no lossless equivalent.

- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218752r1111807_rule` — `U_MS_IIS_10-0_Site_V2R14_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` — Variable source requires one var_ref; Sets/Filters unsupported
- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214463r879643_rule` — `U_MS_IIS_8-5_Site_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` — Variable source requires one var_ref; Sets/Filters unsupported

## Boundary

The generic textual projection now covers `split`, `substring`, `begin`, and `end` with visible empty-prefix `concat`; it preserves raw values/order/multiplicity/status and makes no Rule-specific exception. It does not resolve record-to-text, unsupported-capability, source-family, schema-gap, or conflicting-datatype witnesses above. Runtime/RI equivalence and 55 standalone OVAL parity failures remain held.
