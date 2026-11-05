# Issue #28 all-65 blocker audit

Baseline: **8,892 Rules** across **65 benchmarks** — **4,524 converted**, **4,368 blocked**.

Sources: `niwc-atlantic/scap-content-library@8c8e5dff860af6b1290ee9273a282db24278f8d5`. Schema: `7354a24cdbfe18321153ccaef5d772801a10cd71`; family SHA-256 `63a61b3eb0ca95790721699f5e63b6f5a16b146660b9545a437519b508351db5`.

The ledger uses the 65 public pinned Q3 2026 signed ZIPs. The VM-private failure ledger was not accessed. Primary causes are mutually exclusive; all-blocker counts overlap because dependency probing deliberately reports secondary causes.

## Ranked primary blockers

| Rank | Category | Diagnostic | Rules |
|---:|---|---|---:|
| 1 | `unsupported-construct` | unsupported Test existence: all_exist | 1,750 |
| 2 | `unsupported-selection` | unsupported competing non-OVAL check/selector | 1,653 |
| 3 | `unsupported-selection` | OVAL check imports/exports unsupported | 382 |
| 4 | `unsupported-capability` | unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test | 125 |
| 5 | `unsupported-capability` | unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#independent}sqlext_test | 66 |
| 6 | `unsupported-construct` | unsupported function: count | 37 |
| 7 | `unsupported-construct` | multiple aggregation components need an approved collection expression | 30 |
| 8 | `unsupported-capability` | unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}wmi_test | 20 |
| 9 | `unsupported-construct` | unsupported function: split | 15 |
| 10 | `unsupported-construct` | invalid nil input datatype | 11 |
| 11 | `unsupported-construct` | ordered comparison expansion requires integer source datatype | 10 |
| 12 | `unsupported-construct` | invalid original pattern-path recursion attributes | 10 |
| 13 | `unsupported-construct` | comparator-bearing absence blocked | 9 |
| 14 | `unsupported-construct` | native test name collision 64-bit-architecture-test: oval:mil.disa.stig.ol7:tst:1432 vs oval:mil.disa.stig.ol7:tst:1429 | 9 |
| 15 | `unsupported-capability` | unsupported object capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}wmi_object | 8 |
| 16 | `unsupported-construct` | native test name collision 64-bit-architecture-test: oval:mil.disa.stig.rhel7:tst:1432 vs oval:mil.disa.stig.rhel7:tst:1429 | 8 |
| 17 | `unsupported-construct` | native test name collision audit-32-bit-invocations-of-syscall-with-exit-eperm-test: oval:mil.disa.stig.ind:tst:23044900 vs oval:mil.disa.stig.ind:tst:23044904 | 7 |
| 18 | `unsupported-construct` | unsupported function: substring | 7 |
| 19 | `unsupported-capability` | unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}user_test | 7 |
| 20 | `unsupported-capability` | unsupported object capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#independent}sqlext_object | 6 |

## Variable/function triage

| Construct | Converted | Blocked | Total appearances |
|---|---:|---:|---:|
| `arithmetic` | 0 | 4 | 4 |
| `begin` | 0 | 0 | 0 |
| `concat` | 138 | 161 | 299 |
| `constant_variable` | 230 | 230 | 460 |
| `count` | 0 | 37 | 37 |
| `end` | 0 | 2 | 2 |
| `external_variable` | 0 | 426 | 426 |
| `local_variable` | 268 | 248 | 516 |
| `merge` | 35 | 26 | 61 |
| `regex_capture` | 73 | 55 | 128 |
| `split` | 0 | 23 | 23 |
| `substring` | 0 | 8 | 8 |
| `unique` | 24 | 63 | 87 |

## Recovery order

1. **all_exist** — 1,750 primary Rules. Current 0.4 item_requirement explicitly maps all_exist to one_or_more; no schema change is required.
2. **non_oval_checks** — 1,653 primary Rules. Manual/OCIL choices require preserved manual Assessments, not fabricated automation.
3. **check_import_export** — 382 primary Rules. Bounded native Input/Parameter adapter is the next semantic recovery candidate.
4. **variables_and_functions** — 90 primary Rules. Recover only source-backed forms already admitted by the 0.4 grammar; retain OVAL Cartesian/status/casting behavior.
5. **capability_gaps** — 239 primary Rules. Requires separate capability contracts or owner-approved unsupported/manual treatment.

## Benchmark accounting

| Benchmark | Rules | Converted | Blocked |
|---|---:|---:|---:|
| `U_Active_Directory_Domain_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip` | 36 | 15 | 21 |
| `U_Active_Directory_Forest_V3R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip` | 7 | 4 | 3 |
| `U_Adobe_Acrobat_Pro_DC_Continuous_V2R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip` | 23 | 19 | 4 |
| `U_Adobe_Acrobat_Reader_DC_Continuous_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip` | 26 | 25 | 1 |
| `U_Amazon_Linux_2023_V1R2_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` | 187 | 118 | 69 |
| `U_Apache_Server_2-4_UNIX_Server_V3R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip` | 45 | 9 | 36 |
| `U_Apache_Server_2-4_UNIX_Site_V2R6_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip` | 16 | 3 | 13 |
| `U_Apache_Server_2-4_Windows_Server_V3R3_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip` | 49 | 20 | 29 |
| `U_Apache_Server_2-4_Windows_Site_V2R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip` | 16 | 4 | 12 |
| `U_Apache_Tomcat_Application_Server_9_V3R4_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` | 79 | 0 | 79 |
| `U_Apple_macOS_13_V1R5_STIG_SCAP_1-4_Benchmark-enhancedV7-signed.zip` | 113 | 0 | 113 |
| `U_Apple_macOS_14_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV7-signed.zip` | 156 | 0 | 156 |
| `U_Apple_macOS_15_V1R4_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip` | 160 | 0 | 160 |
| `U_Apple_macOS_26_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV5-signed.zip` | 160 | 0 | 160 |
| `U_CAN_Ubuntu_18-04_LTS_V2R12_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip` | 176 | 63 | 113 |
| `U_CAN_Ubuntu_20-04_LTS_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` | 173 | 116 | 57 |
| `U_CAN_Ubuntu_22-04_LTS_V2R7_STIG_SCAP_1-4_Benchmark-enhancedV10-signed.zip` | 188 | 120 | 68 |
| `U_CAN_Ubuntu_24-04_LTS_V1R5_STIG_SCAP_1-4_Benchmark-enhancedV7-signed.zip` | 194 | 121 | 73 |
| `U_Cisco_IOS-XE_Router_NDM_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` | 42 | 32 | 10 |
| `U_Cisco_IOS-XE_Router_RTR_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` | 97 | 6 | 91 |
| `U_Cisco_IOS-XE_Switch_NDM_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV6-signed.zip` | 42 | 32 | 10 |
| `U_Cisco_IOS_Router_NDM_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV6-signed.zip` | 35 | 24 | 11 |
| `U_Cisco_IOS_Switch_NDM_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV6-signed.zip` | 35 | 24 | 11 |
| `U_F5_NGINX_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` | 32 | 20 | 12 |
| `U_Google_Chrome_V2R11_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip` | 46 | 44 | 2 |
| `U_Kubernetes_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip` | 92 | 61 | 31 |
| `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip` | 33 | 0 | 33 |
| `U_MOZ_Firefox_Windows_V6R8_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` | 33 | 32 | 1 |
| `U_MS_Defender_Antivirus_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV15-signed.zip` | 67 | 59 | 8 |
| `U_MS_DotNet_Framework_4-0_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV15-signed.zip` | 17 | 7 | 10 |
| `U_MS_Edge_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip` | 61 | 56 | 5 |
| `U_MS_Exchange_2019_Edge_Server_V2R2_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` | 68 | 53 | 15 |
| `U_MS_Exchange_2019_Mailbox_Server_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` | 66 | 49 | 17 |
| `U_MS_IE11_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` | 137 | 63 | 74 |
| `U_MS_IIS_10-0_Server_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` | 40 | 19 | 21 |
| `U_MS_IIS_10-0_Site_V2R14_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 44 | 25 | 19 |
| `U_MS_IIS_8-5_Server_V2R7_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` | 43 | 15 | 28 |
| `U_MS_IIS_8-5_Site_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` | 49 | 14 | 35 |
| `U_MS_Office_365_ProPlus_V3R8_STIG_SCAP_1-4_Benchmark-enhancedV11-signed.zip` | 139 | 22 | 117 |
| `U_MS_OneDrive_V2R4_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip` | 12 | 12 | 0 |
| `U_MS_SQL_Server_2016_Database_V3R4_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` | 23 | 0 | 23 |
| `U_MS_SQL_Server_2016_Instance_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV14-signed.zip` | 84 | 4 | 80 |
| `U_MS_SQL_Server_2022_Database_V1R2_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip` | 23 | 0 | 23 |
| `U_MS_SQL_Server_2022_Instance_V1R3_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip` | 79 | 3 | 76 |
| `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` | 267 | 203 | 64 |
| `U_MS_Windows_11_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` | 257 | 220 | 37 |
| `U_MS_Windows_2012_and_2012_R2_DC_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` | 364 | 104 | 260 |
| `U_MS_Windows_2012_and_2012_R2_MS_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` | 329 | 87 | 242 |
| `U_MS_Windows_Defender_Firewall_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV14-signed.zip` | 21 | 0 | 21 |
| `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 272 | 155 | 117 |
| `U_MS_Windows_Server_2019_V3R9_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 282 | 242 | 40 |
| `U_MS_Windows_Server_2022_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 278 | 237 | 41 |
| `U_MS_Windows_Server_2025_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` | 291 | 247 | 44 |
| `U_MS_Windows_Server_DNS_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip` | 81 | 37 | 44 |
| `U_Oracle_Linux_7_V3R3_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip` | 243 | 86 | 157 |
| `U_Oracle_Linux_8_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 376 | 215 | 161 |
| `U_Oracle_Linux_9_V1R4_STIG_SCAP_1-4_Benchmark-enhancedV5-signed.zip` | 448 | 288 | 160 |
| `U_RHEL_7_V3R15_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 244 | 96 | 148 |
| `U_RHEL_8_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV22-signed.zip` | 369 | 219 | 150 |
| `U_RHEL_9_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` | 445 | 301 | 144 |
| `U_SLES_12_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` | 210 | 44 | 166 |
| `U_SLES_15_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 218 | 109 | 109 |
| `U_SOL_11_SPARC_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` | 215 | 113 | 102 |
| `U_SOL_11_X86_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` | 214 | 112 | 102 |
| `U_TOSS_4_V2R7_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip` | 225 | 96 | 129 |

## Reproduction

```sh
PYTHONPATH=src python scripts/audit_issue28_blockers.py \
  --source-dir /path/to/65-pinned-zips \
  --schema-root /path/to/scap-ng@7354a24cdbfe18321153ccaef5d772801a10cd71 \
  --output docs/evidence/issue28/BLOCKER-AUDIT.json
```

This is an authoring conversion report only. It does not claim independent proof, compilation, scanner execution, or compliance results.
