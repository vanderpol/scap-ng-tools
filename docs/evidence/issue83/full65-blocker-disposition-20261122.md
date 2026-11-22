# 65-benchmark blocker disposition — 2026-11-22

This ledger re-audits the 94 raw blocked Rules from the pinned full-65 receipt. It is a source/converter disposition, not runtime or independent OVAL equivalence. No source XML was modified.

## Pinned baseline

- Source commit: `8c8e5dff860af6b1290ee9273a282db24278f8d5`; source archive SHA-256: `a780f91a487ceca1d03d23c0155e7fe612d55db44e27014f9de4e3adc6ce0097`
- Canonical: `2d983fcbd7b2367d567ca8ccc689a378d08905e4`; schema aggregate: `dc650646a24e727e68de242027cca3058683accc531f07bf6ace217609755b24`
- Tools merge baseline: `79ef6550e506903330024d5546df75c0a812f473`
- Full-65 receipt: `external:/tmp/tools-full65-vm-1795372844/full65-source-rule-rebuild.json`, SHA-256 `043a3b5ce0cf988b3f6ab5ffd049813e39857199469a99886031d69d56546592`
- Baseline: 6,493 converted, 94 blocked, 1,403 manual-only; 14 recovered; zero converted-to-blocked regressions.

## Mutually exclusive root causes

| Priority | Root cause | Rules | Disposition |
|---|---|---:|---|
| P2 | `source_invalid_cross_capability_reference` — Source Test/Object/State or filter references violate the exact OVAL family mapping; do not map across capabilities. | 9 | `source-invalid` |
| P2 | `source_invalid_variable_result_datatype` — Source local Variable declaration conflicts with concat/count result semantics; correct upstream source, never add a cast. | 2 | `source-invalid` |
| P3 | `deprecated_windows_accesstoken` — OVAL Windows accesstoken_test deprecated since 5.11; replacement userright_test. | 66 | `deprecated-source` |
| P3 | `deprecated_windows_user` — OVAL Windows user_test deprecated since 5.11; replacement user_sid55_test. | 5 | `deprecated-source` |
| P3 | `deprecated_windows_wmi_transitive_concat` — Raw concat diagnostic is downstream of deprecated Windows wmi_object since 5.7; replacement wmi57_object. | 12 | `deprecated-source` |

There are **zero converter-owned defects** in this 94-row denominator. The 12 `concat` messages are secondary diagnostics: every selected Definition graph contains a deprecated `windows:wmi_object`; they are not evidence of a supported generic concat gap.

## Normative evidence

- `windows-definitions-schema.xsd`, lines 26–46: `accesstoken_test`, deprecated since 5.11, replacement `userright_test`; lines 8173–8193: `user_test`, deprecated since 5.11, replacement `user_sid55_test`; lines 9250–9263: `wmi_object`, deprecated since 5.7, replacement `wmi57_object`.
- `oval-definitions-schema.xsd`, lines 710–711 and 770–802: FunctionGroup/Concat semantics and string result; lines 953–960: Count semantics and numeric count result. The two source declarations are grammar-admitted but semantically inconsistent; the converter correctly refuses implicit casts.
- `windows-definitions-schema.xsd`, patterns `win-def_appcmdtst` and `win-def_appcmdlistconfigtst`; `unix-definitions-schema.xsd`, pattern `unix-def_filetst`; Windows filter patterns `win-def_appcmd_object_verify_filter_state`. These require Test/Object/State and filter references to remain within the declared capability family.

## Affected Rule identities

### `source_invalid_cross_capability_reference` (9)

- `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278400r1172752_rule` — U_F5_NGINX_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip
- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218741r1022677_rule` — U_MS_IIS_10-0_Site_V2R14_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218742r1022679_rule` — U_MS_IIS_10-0_Site_V2R14_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218752r1111807_rule` — U_MS_IIS_10-0_Site_V2R14_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218781r1022700_rule` — U_MS_IIS_10-0_Site_V2R14_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214451r879567_rule` — U_MS_IIS_8-5_Site_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip
- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214452r879568_rule` — U_MS_IIS_8-5_Site_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip
- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214463r879643_rule` — U_MS_IIS_8-5_Site_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip
- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214495r879587_rule` — U_MS_IIS_8-5_Site_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip

### `source_invalid_variable_result_datatype` (2)

- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218814r1067589_rule` — U_MS_IIS_10-0_Server_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip
- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218771r1192784_rule` — U_MS_IIS_10-0_Site_V2R14_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip

### `deprecated_windows_accesstoken` (66)

- `xccdf_mil.disa.stig_rule_SV-220956r958726_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220957r1137691_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220958r958726_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220959r1137691_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220960r958726_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220961r958726_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220962r958726_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220963r958726_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220964r958726_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220965r958726_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220966r958726_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220967r958726_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220968r1137691_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220969r1137691_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220970r1137691_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220971r1137691_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220972r1137691_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220973r958726_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220974r958726_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220975r1138519_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220976r958726_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220977r958726_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220978r958434_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220979r958726_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220980r958726_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220981r958726_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220982r958726_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-220983r958726_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-224997r958472_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-224998r958726_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-224999r958472_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225000r958472_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225001r958472_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225002r958472_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225003r958472_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225004r958672_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225005r958726_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225014r958472_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225015r958472_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225016r958472_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225017r958472_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225018r958472_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225019r958672_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225020r958726_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225070r958726_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225071r958726_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225072r958472_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225073r958726_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225074r958726_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225076r958726_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225077r958726_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225078r958726_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225079r958726_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225080r958726_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225081r958726_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225082r958726_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225083r958726_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225084r958726_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225085r958726_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225086r958434_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225087r958726_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225088r958726_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225089r958726_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225091r958726_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225092r958726_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-225093r958726_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip

### `deprecated_windows_user` (5)

- `xccdf_mil.disa.stig_rule_SV-220952r1051038_rule` — U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip
- `xccdf_mil.disa.stig_rule_SV-253476r1210304_rule` — U_MS_Windows_11_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip
- `xccdf_mil.disa.stig_rule_SV-205657r1153431_rule` — U_MS_Windows_Server_2019_V3R9_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-254239r1153440_rule` — U_MS_Windows_Server_2022_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-277986r1182007_rule` — U_MS_Windows_Server_2025_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip

### `deprecated_windows_wmi_transitive_concat` (12)

- `xccdf_mil.disa.fso_rule_SV-225230r1117185_rule` — U_MS_DotNet_Framework_4-0_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV15-signed.zip
- `xccdf_mil.disa.fso_rule_SV-225232r1050651_rule` — U_MS_DotNet_Framework_4-0_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV15-signed.zip
- `xccdf_mil.disa.fso_rule_SV-225234r1188289_rule` — U_MS_DotNet_Framework_4-0_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV15-signed.zip
- `xccdf_mil.disa.fso_rule_SV-225235r960891_rule` — U_MS_DotNet_Framework_4-0_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV15-signed.zip
- `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-259637r961608_rule` — U_MS_Exchange_2019_Edge_Server_V2R2_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip
- `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-259704r961608_rule` — U_MS_Exchange_2019_Mailbox_Server_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip
- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218795r960963_rule` — U_MS_IIS_10-0_Server_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip
- `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214416r879627_rule` — U_MS_IIS_8-5_Server_V2R7_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip
- `xccdf_mil.disa.stig_rule_SV-224975r958524_rule` — U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-205723r1137695_rule` — U_MS_Windows_Server_2019_V3R9_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-254396r1137695_rule` — U_MS_Windows_Server_2022_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip
- `xccdf_mil.disa.stig_rule_SV-278143r1182092_rule` — U_MS_Windows_Server_2025_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip

## Ranked next actions

1. **P0 release gate:** retain this ledger and fail future qualification if a newly observed source-valid, nondeprecated Rule is assigned to one of these exclusions without evidence.
2. **P2 upstream content:** submit/review source corrections for the two Variable result-type declarations and nine cross-capability references; do not change converter validation.
3. **P3 source policy:** preserve deprecated Rules as explicit dispositions; do not add `accesstoken`, `user`, or legacy `wmi_object` native support.
4. Re-run focused conversion only after a source correction or new converter/canonical pin; runtime execution remains a separate RI qualification responsibility.
