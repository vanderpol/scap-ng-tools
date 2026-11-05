# Issue #28 complete conversion ledger

Source corpus: `niwc-atlantic/scap-content-library@8c8e5dff860af6b1290ee9273a282db24278f8d5`  
Schema family: `63a61b3eb0ca95790721699f5e63b6f5a16b146660b9545a437519b508351db5`  
Rules: **8892** across **65** benchmarks.

## Mutually exclusive classification

| Category | Rules |
|---|---:|
| `automated_converted_proved` | 0 |
| `automated_converted_unproved` | 6785 |
| `manual_only` | 1581 |
| `genuinely_blocked` | 317 |
| `intentionally_excluded` | 209 |

No Rules are independently proved by this authoring ledger.

## Per-benchmark accounting

| Benchmark | Source | Automated | Manual | Blocked | Excluded |
|---|---:|---:|---:|---:|---:|
| U_Active_Directory_Domain_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip | 36 | 17 | 19 | 0 | 0 |
| U_Active_Directory_Forest_V3R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip | 7 | 4 | 3 | 0 | 0 |
| U_Adobe_Acrobat_Pro_DC_Continuous_V2R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip | 23 | 22 | 1 | 0 | 0 |
| U_Adobe_Acrobat_Reader_DC_Continuous_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip | 26 | 25 | 1 | 0 | 0 |
| U_Amazon_Linux_2023_V1R2_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip | 187 | 168 | 17 | 2 | 0 |
| U_Apache_Server_2-4_UNIX_Server_V3R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip | 45 | 22 | 23 | 0 | 0 |
| U_Apache_Server_2-4_UNIX_Site_V2R6_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip | 16 | 6 | 10 | 0 | 0 |
| U_Apache_Server_2-4_Windows_Server_V3R3_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip | 49 | 23 | 26 | 0 | 0 |
| U_Apache_Server_2-4_Windows_Site_V2R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip | 16 | 5 | 11 | 0 | 0 |
| U_Apache_Tomcat_Application_Server_9_V3R4_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip | 79 | 0 | 79 | 0 | 0 |
| U_Apple_macOS_13_V1R5_STIG_SCAP_1-4_Benchmark-enhancedV7-signed.zip | 113 | 102 | 11 | 0 | 0 |
| U_Apple_macOS_14_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV7-signed.zip | 156 | 152 | 4 | 0 | 0 |
| U_Apple_macOS_15_V1R4_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip | 160 | 157 | 3 | 0 | 0 |
| U_Apple_macOS_26_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV5-signed.zip | 160 | 157 | 3 | 0 | 0 |
| U_CAN_Ubuntu_18-04_LTS_V2R12_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip | 176 | 127 | 47 | 2 | 0 |
| U_CAN_Ubuntu_20-04_LTS_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip | 173 | 139 | 34 | 0 | 0 |
| U_CAN_Ubuntu_22-04_LTS_V2R7_STIG_SCAP_1-4_Benchmark-enhancedV10-signed.zip | 188 | 174 | 13 | 1 | 0 |
| U_CAN_Ubuntu_24-04_LTS_V1R5_STIG_SCAP_1-4_Benchmark-enhancedV7-signed.zip | 194 | 177 | 16 | 1 | 0 |
| U_Cisco_IOS-XE_Router_NDM_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip | 42 | 32 | 5 | 5 | 0 |
| U_Cisco_IOS-XE_Router_RTR_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip | 97 | 6 | 91 | 0 | 0 |
| U_Cisco_IOS-XE_Switch_NDM_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV6-signed.zip | 42 | 32 | 5 | 5 | 0 |
| U_Cisco_IOS_Router_NDM_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV6-signed.zip | 35 | 24 | 6 | 5 | 0 |
| U_Cisco_IOS_Switch_NDM_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV6-signed.zip | 35 | 24 | 6 | 5 | 0 |
| U_F5_NGINX_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip | 32 | 21 | 10 | 1 | 0 |
| U_Google_Chrome_V2R11_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip | 46 | 44 | 2 | 0 | 0 |
| U_Kubernetes_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip | 92 | 61 | 31 | 0 | 0 |
| U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip | 33 | 0 | 3 | 30 | 0 |
| U_MOZ_Firefox_Windows_V6R8_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip | 33 | 32 | 1 | 0 | 0 |
| U_MS_Defender_Antivirus_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV15-signed.zip | 67 | 67 | 0 | 0 | 0 |
| U_MS_DotNet_Framework_4-0_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV15-signed.zip | 17 | 9 | 3 | 5 | 0 |
| U_MS_Edge_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip | 61 | 56 | 5 | 0 | 0 |
| U_MS_Exchange_2019_Edge_Server_V2R2_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip | 68 | 53 | 13 | 2 | 0 |
| U_MS_Exchange_2019_Mailbox_Server_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip | 66 | 50 | 15 | 1 | 0 |
| U_MS_IE11_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip | 137 | 137 | 0 | 0 | 0 |
| U_MS_IIS_10-0_Server_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip | 40 | 22 | 15 | 3 | 0 |
| U_MS_IIS_10-0_Site_V2R14_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip | 44 | 26 | 11 | 7 | 0 |
| U_MS_IIS_8-5_Server_V2R7_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip | 43 | 18 | 24 | 1 | 0 |
| U_MS_IIS_8-5_Site_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip | 49 | 15 | 29 | 5 | 0 |
| U_MS_Office_365_ProPlus_V3R8_STIG_SCAP_1-4_Benchmark-enhancedV11-signed.zip | 139 | 138 | 1 | 0 | 0 |
| U_MS_OneDrive_V2R4_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip | 12 | 12 | 0 | 0 | 0 |
| U_MS_SQL_Server_2016_Database_V3R4_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip | 23 | 0 | 0 | 0 | 23 |
| U_MS_SQL_Server_2016_Instance_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV14-signed.zip | 84 | 0 | 0 | 0 | 84 |
| U_MS_SQL_Server_2022_Database_V1R2_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip | 23 | 0 | 0 | 0 | 23 |
| U_MS_SQL_Server_2022_Instance_V1R3_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip | 79 | 0 | 0 | 0 | 79 |
| U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip | 267 | 225 | 12 | 30 | 0 |
| U_MS_Windows_11_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip | 257 | 244 | 11 | 2 | 0 |
| U_MS_Windows_2012_and_2012_R2_DC_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip | 364 | 210 | 96 | 58 | 0 |
| U_MS_Windows_2012_and_2012_R2_MS_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip | 329 | 191 | 82 | 56 | 0 |
| U_MS_Windows_Defender_Firewall_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV14-signed.zip | 21 | 20 | 1 | 0 | 0 |
| U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip | 272 | 198 | 28 | 46 | 0 |
| U_MS_Windows_Server_2019_V3R9_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip | 282 | 252 | 27 | 3 | 0 |
| U_MS_Windows_Server_2022_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip | 278 | 248 | 27 | 3 | 0 |
| U_MS_Windows_Server_2025_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip | 291 | 258 | 30 | 3 | 0 |
| U_MS_Windows_Server_DNS_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip | 81 | 39 | 40 | 2 | 0 |
| U_Oracle_Linux_7_V3R3_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip | 243 | 169 | 72 | 2 | 0 |
| U_Oracle_Linux_8_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip | 376 | 322 | 52 | 2 | 0 |
| U_Oracle_Linux_9_V1R4_STIG_SCAP_1-4_Benchmark-enhancedV5-signed.zip | 448 | 399 | 40 | 9 | 0 |
| U_RHEL_7_V3R15_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip | 244 | 185 | 58 | 1 | 0 |
| U_RHEL_8_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV22-signed.zip | 369 | 330 | 32 | 7 | 0 |
| U_RHEL_9_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip | 445 | 409 | 27 | 9 | 0 |
| U_SLES_12_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip | 210 | 121 | 89 | 0 | 0 |
| U_SLES_15_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip | 218 | 135 | 83 | 0 | 0 |
| U_SOL_11_SPARC_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip | 215 | 140 | 74 | 1 | 0 |
| U_SOL_11_X86_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip | 214 | 140 | 73 | 1 | 0 |
| U_TOSS_4_V2R7_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip | 225 | 194 | 30 | 1 | 0 |

## Primary blocker root causes

| Category | Root cause | Rules | Representative source Rules |
|---|---|---:|---|
| unsupported-capability | unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test | 125 | xccdf_mil.disa.stig_rule_SV-220956r958726_rule, xccdf_mil.disa.stig_rule_SV-220957r1137691_rule, xccdf_mil.disa.stig_rule_SV-220958r958726_rule |
| schema-semantic | native function contract admission: count | 37 | xccdf_mil.disa.stig_rule_SV-274160r1120663_rule, xccdf_mil.disa.stig_rule_SV-260543r958482_rule, xccdf_mil.disa.stig_rule_SV-270720r1066649_rule |
| unsupported-construct | XCCDF Value operator requires an explicit constraint adapter | 36 | xccdf_mil.disa.fso_rule_SV-226057r794277_rule, xccdf_mil.disa.fso_rule_SV-226058r852055_rule, xccdf_mil.disa.fso_rule_SV-226059r794296_rule |
| unsupported-construct | multiple aggregation components need an approved collection expression | 30 | xccdf_mil.disa.stig_rule_SV-251546r1201983_rule, xccdf_mil.disa.stig_rule_SV-251547r1067550_rule, xccdf_mil.disa.stig_rule_SV-251548r1067552_rule |
| unsupported-capability | unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}wmi_test | 20 | xccdf_mil.disa.fso_rule_SV-226065r794383_rule, xccdf_mil.disa.fso_rule_SV-226066r794792_rule, xccdf_mil.disa.fso_rule_SV-226067r794794_rule |
| schema-semantic | native function contract admission: split | 19 | xccdf_mil.disa.stig_rule_SV-219147r958472_rule, xccdf_mil.disa.stig_rule_SV-219148r958472_rule, xccdf_mil.disa.stig_rule_SV-271653r1091671_rule |
| unsupported-capability | unsupported object capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}wmi_object | 14 | xccdf_mil.disa.fso_rule_SV-225230r1117185_rule, xccdf_mil.disa.fso_rule_SV-225232r1050651_rule, xccdf_mil.disa.fso_rule_SV-225234r1188289_rule |
| unsupported-capability | unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}user_test | 8 | xccdf_mil.disa.stig_rule_SV-220952r1051038_rule, xccdf_mil.disa.stig_rule_SV-253476r1210304_rule, xccdf_mil.disa.fso_rule_SV-225448r569185_rule |
| unsupported-construct | invalid original pattern-path recursion attributes | 7 | xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218801r961083_rule, xccdf_mil.disa.stig_rule_SV-220723r991589_rule, xccdf_mil.disa.stig_rule_SV-253280r991589_rule |
| schema-semantic | native function contract admission: arithmetic | 3 | xccdf_mil.disa.stig_rule_SV-274067r1120653_rule, xccdf_mil.disa.stig_rule_SV-271596r1091500_rule, xccdf_mil.disa.stig_rule_SV-258155r1045300_rule |
| schema-semantic | native Variable declared/derived datatype mismatch | 3 | xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218762r1192782_rule, xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218778r961863_rule, xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214492r879887_rule |
| unsupported-construct | check-export source/Variable datatype mismatch | 2 | xccdf_mil.disa.fso_rule_SV-226276r794552_rule, xccdf_mil.disa.fso_rule_SV-225453r569185_rule |
| unsupported-construct | unsupported State field/namespace | 2 | xccdf_mil.disa.stig_rule_SV-221653r1015161_rule, xccdf_mil.disa.stig_rule_SV-214799r991589_rule |
| unsupported-capability | state capability mismatch: oval:navy.navwar.niwcatlantic.scc.nginx:ste:27840004 | 1 | xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278400r1172752_rule |
| schema-semantic | native traversal contract admission | 1 | xccdf_mil.disa.fso_rule_SV-225223r961038_rule |
| schema-semantic | native function contract admission: substring | 1 | xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-259592r961095_rule |
| unsupported-construct | Variable cast outside bounded proof | 1 | xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218814r1067589_rule |
| unsupported-capability | state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.10.site:ste:21874102 | 1 | xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218741r1022677_rule |
| unsupported-capability | state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.10.site:ste:21874205 | 1 | xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218742r1022679_rule |
| unsupported-capability | state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.10.site:ste:21878101 | 1 | xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218781r1022700_rule |
| unsupported-capability | state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.8.5.site:ste:80 | 1 | xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214451r879567_rule |
| unsupported-capability | state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.8.5.site:ste:93 | 1 | xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214452r879568_rule |
| unsupported-capability | state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.8.5.site:ste:180 | 1 | xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214495r879587_rule |
| unsupported-construct | Assessment Input function composition requires a supported typed expression | 1 | xccdf_mil.disa.stig_rule_SV-221718r991590_rule |

## Verification status

The ledger was rebuilt from the pinned source ZIPs with SQLEXT-dependent SQL benchmarks intentionally excluded. Source Rule IDs, check selection, source hashes, raw blocker diagnostics, and provenance remain in `COMPLETE-LEDGER.json`. Aggregate blocker rows normalize generated filenames and AST payloads into root causes; no raw diagnostic is discarded.

All automated Rules are **converted but unproved**; none is promoted by YAML/schema admission or compilation. This tools branch has no independent scanner/OVAL comparison or compiler qualification, so `automated_converted_proved` remains zero.
