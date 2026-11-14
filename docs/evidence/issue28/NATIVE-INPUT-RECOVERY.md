# Issue #28 native Input/Parameter recovery

The opt-in candidate converts **6,531** of **8,892** Rules and leaves **2,361** blocked.

Compared with the original baseline, this is **+2,007 Rules**, with **0 regressions**. The delta includes 1,716 `all_exist` recoveries from PR #30 and 291 bounded check-import/export recoveries.

Native recovery accepts only explicit `check-export` -> XCCDF `Value` bindings with matching OVAL datatype, exact cardinality, and supported `equals`/allowed-value semantics. Other Value operators remain blocked rather than coerced. Source Variable/Value identities and the unproved runtime-binding warning remain in provenance.

## Remaining primary blockers

| Category | Diagnostic | Rules |
|---|---|---:|
| `unsupported-selection` | unsupported competing non-OVAL check/selector | 1,653 |
| `unsupported-capability` | unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test | 125 |
| `unsupported-capability` | unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#independent}sqlext_test | 66 |
| `unsupported-construct` | unsupported function: count | 37 |
| `unsupported-construct` | XCCDF Value operator requires an explicit constraint adapter | 36 |
| `unsupported-construct` | multiple aggregation components need an approved collection expression | 30 |
| `unsupported-capability` | unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}wmi_test | 20 |
| `unsupported-construct` | unsupported function: split | 17 |
| `unsupported-construct` | native test name collision check-if-the-sharepoint-designer-2013-key-is-present-test: oval:mil.disa.stig.sharepointdesigner2013:tst:1 vs oval:mil.disa.stig.sharepointdesigner2013:tst:2 | 13 |
| `unsupported-construct` | invalid nil input datatype | 11 |
| `unsupported-construct` | ordered comparison expansion requires integer source datatype | 10 |
| `unsupported-construct` | invalid original pattern-path recursion attributes | 10 |
| `unsupported-construct` | native test name collision 64-bit-architecture-test: oval:mil.disa.stig.ol7:tst:1432 vs oval:mil.disa.stig.ol7:tst:1429 | 10 |
| `unsupported-construct` | comparator-bearing absence blocked | 9 |
| `unsupported-construct` | native test name collision 64-bit-architecture-test: oval:mil.disa.stig.rhel7:tst:1432 vs oval:mil.disa.stig.rhel7:tst:1429 | 9 |
| `unsupported-construct` | native variable name collision local-variable-lsetxattr-variable: oval:mil.disa.stig.defs:var:25303500 vs oval:mil.disa.stig.defs:var:25303501 | 8 |
| `unsupported-capability` | unsupported object capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}wmi_object | 8 |
| `unsupported-capability` | unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}user_test | 8 |
| `unsupported-construct` | native test name collision audit-32-bit-invocations-of-syscall-with-exit-eperm-test: oval:mil.disa.stig.ind:tst:23044900 vs oval:mil.disa.stig.ind:tst:23044904 | 7 |
| `unsupported-construct` | unsupported function: substring | 7 |

## Benchmark delta

| Benchmark | Rules | Before | After | Recovered |
|---|---:|---:|---:|---:|
| `U_Active_Directory_Domain_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip` | 36 | 15 | 15 | +0 |
| `U_Active_Directory_Forest_V3R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip` | 7 | 4 | 4 | +0 |
| `U_Adobe_Acrobat_Pro_DC_Continuous_V2R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip` | 23 | 19 | 22 | +3 |
| `U_Adobe_Acrobat_Reader_DC_Continuous_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip` | 26 | 25 | 25 | +0 |
| `U_Amazon_Linux_2023_V1R2_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` | 187 | 118 | 164 | +46 |
| `U_Apache_Server_2-4_UNIX_Server_V3R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip` | 45 | 9 | 9 | +0 |
| `U_Apache_Server_2-4_UNIX_Site_V2R6_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip` | 16 | 3 | 3 | +0 |
| `U_Apache_Server_2-4_Windows_Server_V3R3_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip` | 49 | 20 | 20 | +0 |
| `U_Apache_Server_2-4_Windows_Site_V2R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip` | 16 | 4 | 5 | +1 |
| `U_Apache_Tomcat_Application_Server_9_V3R4_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` | 79 | 0 | 0 | +0 |
| `U_Apple_macOS_13_V1R5_STIG_SCAP_1-4_Benchmark-enhancedV7-signed.zip` | 113 | 0 | 102 | +102 |
| `U_Apple_macOS_14_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV7-signed.zip` | 156 | 0 | 152 | +152 |
| `U_Apple_macOS_15_V1R4_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip` | 160 | 0 | 157 | +157 |
| `U_Apple_macOS_26_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV5-signed.zip` | 160 | 0 | 157 | +157 |
| `U_CAN_Ubuntu_18-04_LTS_V2R12_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip` | 176 | 63 | 119 | +56 |
| `U_CAN_Ubuntu_20-04_LTS_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` | 173 | 116 | 133 | +17 |
| `U_CAN_Ubuntu_22-04_LTS_V2R7_STIG_SCAP_1-4_Benchmark-enhancedV10-signed.zip` | 188 | 120 | 168 | +48 |
| `U_CAN_Ubuntu_24-04_LTS_V1R5_STIG_SCAP_1-4_Benchmark-enhancedV7-signed.zip` | 194 | 121 | 171 | +50 |
| `U_Cisco_IOS-XE_Router_NDM_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` | 42 | 32 | 32 | +0 |
| `U_Cisco_IOS-XE_Router_RTR_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` | 97 | 6 | 6 | +0 |
| `U_Cisco_IOS-XE_Switch_NDM_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV6-signed.zip` | 42 | 32 | 32 | +0 |
| `U_Cisco_IOS_Router_NDM_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV6-signed.zip` | 35 | 24 | 24 | +0 |
| `U_Cisco_IOS_Switch_NDM_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV6-signed.zip` | 35 | 24 | 24 | +0 |
| `U_F5_NGINX_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` | 32 | 20 | 20 | +0 |
| `U_Google_Chrome_V2R11_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip` | 46 | 44 | 44 | +0 |
| `U_Kubernetes_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip` | 92 | 61 | 61 | +0 |
| `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip` | 33 | 0 | 0 | +0 |
| `U_MOZ_Firefox_Windows_V6R8_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` | 33 | 32 | 32 | +0 |
| `U_MS_Defender_Antivirus_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV15-signed.zip` | 67 | 59 | 67 | +8 |
| `U_MS_DotNet_Framework_4-0_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV15-signed.zip` | 17 | 7 | 7 | +0 |
| `U_MS_Edge_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip` | 61 | 56 | 56 | +0 |
| `U_MS_Exchange_2019_Edge_Server_V2R2_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` | 68 | 53 | 53 | +0 |
| `U_MS_Exchange_2019_Mailbox_Server_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` | 66 | 49 | 49 | +0 |
| `U_MS_IE11_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` | 137 | 63 | 117 | +54 |
| `U_MS_IIS_10-0_Server_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` | 40 | 19 | 19 | +0 |
| `U_MS_IIS_10-0_Site_V2R14_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 44 | 25 | 25 | +0 |
| `U_MS_IIS_8-5_Server_V2R7_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` | 43 | 15 | 15 | +0 |
| `U_MS_IIS_8-5_Site_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` | 49 | 14 | 14 | +0 |
| `U_MS_Office_365_ProPlus_V3R8_STIG_SCAP_1-4_Benchmark-enhancedV11-signed.zip` | 139 | 22 | 125 | +103 |
| `U_MS_OneDrive_V2R4_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip` | 12 | 12 | 12 | +0 |
| `U_MS_SQL_Server_2016_Database_V3R4_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` | 23 | 0 | 0 | +0 |
| `U_MS_SQL_Server_2016_Instance_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV14-signed.zip` | 84 | 4 | 4 | +0 |
| `U_MS_SQL_Server_2022_Database_V1R2_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip` | 23 | 0 | 0 | +0 |
| `U_MS_SQL_Server_2022_Instance_V1R3_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip` | 79 | 3 | 3 | +0 |
| `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` | 267 | 203 | 216 | +13 |
| `U_MS_Windows_11_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` | 257 | 220 | 234 | +14 |
| `U_MS_Windows_2012_and_2012_R2_DC_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` | 364 | 104 | 205 | +101 |
| `U_MS_Windows_2012_and_2012_R2_MS_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` | 329 | 87 | 187 | +100 |
| `U_MS_Windows_Defender_Firewall_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV14-signed.zip` | 21 | 0 | 1 | +1 |
| `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 272 | 155 | 193 | +38 |
| `U_MS_Windows_Server_2019_V3R9_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 282 | 242 | 249 | +7 |
| `U_MS_Windows_Server_2022_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 278 | 237 | 244 | +7 |
| `U_MS_Windows_Server_2025_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` | 291 | 247 | 255 | +8 |
| `U_MS_Windows_Server_DNS_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip` | 81 | 37 | 37 | +0 |
| `U_Oracle_Linux_7_V3R3_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip` | 243 | 86 | 154 | +68 |
| `U_Oracle_Linux_8_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 376 | 215 | 313 | +98 |
| `U_Oracle_Linux_9_V1R4_STIG_SCAP_1-4_Benchmark-enhancedV5-signed.zip` | 448 | 288 | 392 | +104 |
| `U_RHEL_7_V3R15_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 244 | 96 | 167 | +71 |
| `U_RHEL_8_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV22-signed.zip` | 369 | 219 | 318 | +99 |
| `U_RHEL_9_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` | 445 | 301 | 403 | +102 |
| `U_SLES_12_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` | 210 | 44 | 115 | +71 |
| `U_SLES_15_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 218 | 109 | 130 | +21 |
| `U_SOL_11_SPARC_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` | 215 | 113 | 136 | +23 |
| `U_SOL_11_X86_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` | 214 | 112 | 136 | +24 |
| `U_TOSS_4_V2R7_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip` | 225 | 96 | 179 | +83 |

## Qualification

- Recovery remains opt-in via `--recover-native` / `native_recovery=True`; historical default and goldens are unchanged.
- Full 65-source candidate: 6,531 converted / 2,361 blocked; all 65 Rule counts reconcile to 8,892.
- Source-backed IE11 check-export fixture passed with native Input/Parameter provenance.
- This is authoring conversion only; no compiler, independent proof, scanner, or compliance claim.

Machine-readable evidence: [`NATIVE-INPUT-RECOVERY.json`](NATIVE-INPUT-RECOVERY.json).
