# Tools PR #43: full-65 qualification evidence

Status: **PASS**

PASS means source-preserving conversion and current-schema authoring validation only; no independent OVAL semantic proof or scanner qualification is claimed.

## Pinned contracts

- Tools commit: `1de1798`
- Schema commit: `f7e5e845d21e3a38ec5dc5ec04228b763acd9c5b`
- Schema version: `0.4.0`
- Schema snapshot aggregate SHA-256: `63a61b3eb0ca95790721699f5e63b6f5a16b146660b9545a437519b508351db5`
- Unapproved schema PR #27: **not adopted**
- Unsupported OVAL functions: remain blocked; no proof promotion

## Per-Benchmark ledger

| Benchmark | Rules | Converted | Blocked | Native docs | OCIL/source Rules retained | Repeat stage | Repeat package | Result |
|---|---:|---:|---:|---:|---:|---|---|---|
| `U_Active_Directory_Domain_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV2-signed` | 36 | 15 | 21 | 64 | 36 | PASS | PASS | **PASS** |
| `U_Active_Directory_Forest_V3R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed` | 7 | 4 | 3 | 20 | 7 | PASS | PASS | **PASS** |
| `U_Adobe_Acrobat_Pro_DC_Continuous_V2R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed` | 23 | 19 | 4 | 80 | 23 | PASS | PASS | **PASS** |
| `U_Adobe_Acrobat_Reader_DC_Continuous_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV12-signed` | 26 | 25 | 1 | 104 | 26 | PASS | PASS | **PASS** |
| `U_Amazon_Linux_2023_V1R2_STIG_SCAP_1-4_Benchmark-enhancedV1-signed` | 187 | 118 | 69 | 476 | 187 | PASS | PASS | **PASS** |
| `U_Apache_Server_2-4_UNIX_Server_V3R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed` | 45 | 9 | 36 | 40 | 45 | PASS | PASS | **PASS** |
| `U_Apache_Server_2-4_UNIX_Site_V2R6_STIG_SCAP_1-4_Benchmark-enhancedV2-signed` | 16 | 3 | 13 | 16 | 16 | PASS | PASS | **PASS** |
| `U_Apache_Server_2-4_Windows_Server_V3R3_STIG_SCAP_1-4_Benchmark-enhancedV2-signed` | 49 | 20 | 29 | 84 | 49 | PASS | PASS | **PASS** |
| `U_Apache_Server_2-4_Windows_Site_V2R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed` | 16 | 4 | 12 | 20 | 16 | PASS | PASS | **PASS** |
| `U_Apache_Tomcat_Application_Server_9_V3R4_STIG_SCAP_1-4_Benchmark-enhancedV1-signed` | 79 | 0 | 79 | 0 | 79 | PASS | PASS | **PASS** |
| `U_Apple_macOS_13_V1R5_STIG_SCAP_1-4_Benchmark-enhancedV7-signed` | 113 | 0 | 113 | 0 | 113 | PASS | PASS | **PASS** |
| `U_Apple_macOS_14_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV7-signed` | 156 | 0 | 156 | 0 | 156 | PASS | PASS | **PASS** |
| `U_Apple_macOS_15_V1R4_STIG_SCAP_1-4_Benchmark-enhancedV8-signed` | 160 | 0 | 160 | 0 | 160 | PASS | PASS | **PASS** |
| `U_Apple_macOS_26_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV5-signed` | 160 | 0 | 160 | 0 | 160 | PASS | PASS | **PASS** |
| `U_CAN_Ubuntu_18-04_LTS_V2R12_STIG_SCAP_1-4_Benchmark-enhancedV16-signed` | 176 | 64 | 112 | 260 | 176 | PASS | PASS | **PASS** |
| `U_CAN_Ubuntu_20-04_LTS_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed` | 173 | 116 | 57 | 468 | 173 | PASS | PASS | **PASS** |
| `U_CAN_Ubuntu_22-04_LTS_V2R7_STIG_SCAP_1-4_Benchmark-enhancedV10-signed` | 188 | 120 | 68 | 484 | 188 | PASS | PASS | **PASS** |
| `U_CAN_Ubuntu_24-04_LTS_V1R5_STIG_SCAP_1-4_Benchmark-enhancedV7-signed` | 194 | 121 | 73 | 488 | 194 | PASS | PASS | **PASS** |
| `U_Cisco_IOS-XE_Router_NDM_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed` | 42 | 32 | 10 | 132 | 42 | PASS | PASS | **PASS** |
| `U_Cisco_IOS-XE_Router_RTR_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed` | 97 | 6 | 91 | 28 | 97 | PASS | PASS | **PASS** |
| `U_Cisco_IOS-XE_Switch_NDM_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV6-signed` | 42 | 32 | 10 | 132 | 42 | PASS | PASS | **PASS** |
| `U_Cisco_IOS_Router_NDM_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV6-signed` | 35 | 24 | 11 | 100 | 35 | PASS | PASS | **PASS** |
| `U_Cisco_IOS_Switch_NDM_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV6-signed` | 35 | 24 | 11 | 100 | 35 | PASS | PASS | **PASS** |
| `U_F5_NGINX_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV1-signed` | 32 | 20 | 12 | 84 | 32 | PASS | PASS | **PASS** |
| `U_Google_Chrome_V2R11_STIG_SCAP_1-4_Benchmark-enhancedV16-signed` | 46 | 44 | 2 | 180 | 46 | PASS | PASS | **PASS** |
| `U_Kubernetes_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV8-signed` | 92 | 61 | 31 | 248 | 92 | PASS | PASS | **PASS** |
| `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed` | 33 | 0 | 33 | 0 | 33 | PASS | PASS | **PASS** |
| `U_MOZ_Firefox_Windows_V6R8_STIG_SCAP_1-4_Benchmark-enhancedV13-signed` | 33 | 32 | 1 | 132 | 33 | PASS | PASS | **PASS** |
| `U_MS_Defender_Antivirus_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV15-signed` | 67 | 59 | 8 | 240 | 67 | PASS | PASS | **PASS** |
| `U_MS_DotNet_Framework_4-0_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV15-signed` | 17 | 8 | 9 | 36 | 17 | PASS | PASS | **PASS** |
| `U_MS_Edge_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV16-signed` | 61 | 56 | 5 | 228 | 61 | PASS | PASS | **PASS** |
| `U_MS_Exchange_2019_Edge_Server_V2R2_STIG_SCAP_1-4_Benchmark-enhancedV1-signed` | 68 | 53 | 15 | 216 | 68 | PASS | PASS | **PASS** |
| `U_MS_Exchange_2019_Mailbox_Server_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV1-signed` | 66 | 49 | 17 | 200 | 66 | PASS | PASS | **PASS** |
| `U_MS_IE11_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV17-signed` | 137 | 63 | 74 | 256 | 137 | PASS | PASS | **PASS** |
| `U_MS_IIS_10-0_Server_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV18-signed` | 40 | 19 | 21 | 80 | 40 | PASS | PASS | **PASS** |
| `U_MS_IIS_10-0_Site_V2R14_STIG_SCAP_1-4_Benchmark-enhancedV19-signed` | 44 | 25 | 19 | 104 | 44 | PASS | PASS | **PASS** |
| `U_MS_IIS_8-5_Server_V2R7_STIG_SCAP_1-4_Benchmark-enhancedV13-signed` | 43 | 16 | 27 | 68 | 43 | PASS | PASS | **PASS** |
| `U_MS_IIS_8-5_Site_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed` | 49 | 15 | 34 | 64 | 49 | PASS | PASS | **PASS** |
| `U_MS_Office_365_ProPlus_V3R8_STIG_SCAP_1-4_Benchmark-enhancedV11-signed` | 139 | 22 | 117 | 92 | 139 | PASS | PASS | **PASS** |
| `U_MS_OneDrive_V2R4_STIG_SCAP_1-4_Benchmark-enhancedV12-signed` | 12 | 12 | 0 | 52 | 12 | PASS | PASS | **PASS** |
| `U_MS_SQL_Server_2016_Database_V3R4_STIG_SCAP_1-4_Benchmark-enhancedV13-signed` | 23 | 0 | 23 | 0 | 23 | PASS | PASS | **PASS** |
| `U_MS_SQL_Server_2016_Instance_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV14-signed` | 84 | 4 | 80 | 20 | 84 | PASS | PASS | **PASS** |
| `U_MS_SQL_Server_2022_Database_V1R2_STIG_SCAP_1-4_Benchmark-enhancedV8-signed` | 23 | 0 | 23 | 0 | 23 | PASS | PASS | **PASS** |
| `U_MS_SQL_Server_2022_Instance_V1R3_STIG_SCAP_1-4_Benchmark-enhancedV8-signed` | 79 | 3 | 76 | 16 | 79 | PASS | PASS | **PASS** |
| `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed` | 267 | 203 | 64 | 816 | 267 | PASS | PASS | **PASS** |
| `U_MS_Windows_11_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV18-signed` | 257 | 220 | 37 | 884 | 257 | PASS | PASS | **PASS** |
| `U_MS_Windows_2012_and_2012_R2_DC_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV13-signed` | 364 | 104 | 260 | 420 | 364 | PASS | PASS | **PASS** |
| `U_MS_Windows_2012_and_2012_R2_MS_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV13-signed` | 329 | 87 | 242 | 352 | 329 | PASS | PASS | **PASS** |
| `U_MS_Windows_Defender_Firewall_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV14-signed` | 21 | 0 | 21 | 0 | 21 | PASS | PASS | **PASS** |
| `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed` | 272 | 156 | 116 | 628 | 272 | PASS | PASS | **PASS** |
| `U_MS_Windows_Server_2019_V3R9_STIG_SCAP_1-4_Benchmark-enhancedV19-signed` | 282 | 242 | 40 | 972 | 282 | PASS | PASS | **PASS** |
| `U_MS_Windows_Server_2022_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV19-signed` | 278 | 237 | 41 | 952 | 278 | PASS | PASS | **PASS** |
| `U_MS_Windows_Server_2025_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV1-signed` | 291 | 247 | 44 | 992 | 291 | PASS | PASS | **PASS** |
| `U_MS_Windows_Server_DNS_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV8-signed` | 81 | 37 | 44 | 152 | 81 | PASS | PASS | **PASS** |
| `U_Oracle_Linux_7_V3R3_STIG_SCAP_1-4_Benchmark-enhancedV16-signed` | 243 | 86 | 157 | 348 | 243 | PASS | PASS | **PASS** |
| `U_Oracle_Linux_8_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV19-signed` | 376 | 216 | 160 | 868 | 376 | PASS | PASS | **PASS** |
| `U_Oracle_Linux_9_V1R4_STIG_SCAP_1-4_Benchmark-enhancedV5-signed` | 448 | 290 | 158 | 1164 | 448 | PASS | PASS | **PASS** |
| `U_RHEL_7_V3R15_STIG_SCAP_1-4_Benchmark-enhancedV19-signed` | 244 | 96 | 148 | 388 | 244 | PASS | PASS | **PASS** |
| `U_RHEL_8_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV22-signed` | 369 | 221 | 148 | 888 | 369 | PASS | PASS | **PASS** |
| `U_RHEL_9_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed` | 445 | 302 | 143 | 1212 | 445 | PASS | PASS | **PASS** |
| `U_SLES_12_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV17-signed` | 210 | 45 | 165 | 184 | 210 | PASS | PASS | **PASS** |
| `U_SLES_15_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV19-signed` | 218 | 110 | 108 | 444 | 218 | PASS | PASS | **PASS** |
| `U_SOL_11_SPARC_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed` | 215 | 113 | 102 | 456 | 215 | PASS | PASS | **PASS** |
| `U_SOL_11_X86_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed` | 214 | 112 | 102 | 452 | 214 | PASS | PASS | **PASS** |
| `U_TOSS_4_V2R7_STIG_SCAP_1-4_Benchmark-enhancedV8-signed` | 225 | 97 | 128 | 392 | 225 | PASS | PASS | **PASS** |

## Totals

- Source Rules: **8892** (complete historical 8,892-Rule inventory)
- Automated converted, current-schema validated, unproved: **4538**
- Blocked with explicit diagnostics: **4354**
- Native JSON/YAML documents validated: **18376**
- Original source OCIL/manual Rule IDs retained: **8892**
- Independently proved: **0 claimed**

## Qualification gates

- 65/65 source ZIP SHA-256 and source Rule accounting passed.
- 65/65 current frozen-schema native JSON/YAML validation passed for first and repeated generation.
- 65/65 first/repeat stage trees and package trees are byte-identical.
- Original source ZIPs, XML datastream members, Rule IDs, and OCIL/manual source records are retained; no native manual equivalence was fabricated.
- Windows Server 2012/2012 R2 streams are present only as preserved historical source/pipeline records; they are not an active modernization/proof claim.
- No goldens, merges, releases, or VS Code files were changed.

## Evidence

Machine-readable per-stream hashes, source bytes, source Git blob IDs, blocker categories, unsupported-function holds, and validation errors are in `PR43-FULL65-QUALIFICATION.json`.

## Qualification boundary

This is source-preserving conversion and current-schema authoring validation. It is not independent OVAL semantic equivalence proof, compiler/scanner qualification, or a claim that blocked Rules are converted.
