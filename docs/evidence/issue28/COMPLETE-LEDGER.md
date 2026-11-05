# Issue #28 complete conversion ledger

Source corpus: `niwc-atlantic/scap-content-library@8c8e5dff860af6b1290ee9273a282db24278f8d5`  
Schema family: `63a61b3eb0ca95790721699f5e63b6f5a16b146660b9545a437519b508351db5`  
Rules: **8892** across **65** benchmarks.

## Mutually exclusive classification

| Category | Rules |
|---|---:|
| `automated_converted_proved` | 0 |
| `automated_converted_unproved` | 6775 |
| `manual_only` | 1581 |
| `genuinely_blocked` | 327 |
| `intentionally_excluded` | 209 |

No Rules are independently proved by this authoring ledger.

## Per-benchmark accounting

| Benchmark | Source | Automated | Manual | Blocked | Excluded |
|---|---:|---:|---:|---:|---:|
| `U_Active_Directory_Domain_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip` | 36 | 17 | 19 | 0 | 0 |
| `U_Active_Directory_Forest_V3R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip` | 7 | 4 | 3 | 0 | 0 |
| `U_Adobe_Acrobat_Pro_DC_Continuous_V2R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip` | 23 | 22 | 1 | 0 | 0 |
| `U_Adobe_Acrobat_Reader_DC_Continuous_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip` | 26 | 25 | 1 | 0 | 0 |
| `U_Amazon_Linux_2023_V1R2_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` | 187 | 168 | 17 | 2 | 0 |
| `U_Apache_Server_2-4_UNIX_Server_V3R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip` | 45 | 22 | 23 | 0 | 0 |
| `U_Apache_Server_2-4_UNIX_Site_V2R6_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip` | 16 | 6 | 10 | 0 | 0 |
| `U_Apache_Server_2-4_Windows_Server_V3R3_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip` | 49 | 23 | 26 | 0 | 0 |
| `U_Apache_Server_2-4_Windows_Site_V2R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip` | 16 | 5 | 11 | 0 | 0 |
| `U_Apache_Tomcat_Application_Server_9_V3R4_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` | 79 | 0 | 79 | 0 | 0 |
| `U_Apple_macOS_13_V1R5_STIG_SCAP_1-4_Benchmark-enhancedV7-signed.zip` | 113 | 102 | 11 | 0 | 0 |
| `U_Apple_macOS_14_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV7-signed.zip` | 156 | 152 | 4 | 0 | 0 |
| `U_Apple_macOS_15_V1R4_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip` | 160 | 157 | 3 | 0 | 0 |
| `U_Apple_macOS_26_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV5-signed.zip` | 160 | 157 | 3 | 0 | 0 |
| `U_CAN_Ubuntu_18-04_LTS_V2R12_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip` | 176 | 126 | 47 | 3 | 0 |
| `U_CAN_Ubuntu_20-04_LTS_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` | 173 | 138 | 34 | 1 | 0 |
| `U_CAN_Ubuntu_22-04_LTS_V2R7_STIG_SCAP_1-4_Benchmark-enhancedV10-signed.zip` | 188 | 173 | 13 | 2 | 0 |
| `U_CAN_Ubuntu_24-04_LTS_V1R5_STIG_SCAP_1-4_Benchmark-enhancedV7-signed.zip` | 194 | 176 | 16 | 2 | 0 |
| `U_Cisco_IOS-XE_Router_NDM_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` | 42 | 32 | 5 | 5 | 0 |
| `U_Cisco_IOS-XE_Router_RTR_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` | 97 | 6 | 91 | 0 | 0 |
| `U_Cisco_IOS-XE_Switch_NDM_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV6-signed.zip` | 42 | 32 | 5 | 5 | 0 |
| `U_Cisco_IOS_Router_NDM_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV6-signed.zip` | 35 | 24 | 6 | 5 | 0 |
| `U_Cisco_IOS_Switch_NDM_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV6-signed.zip` | 35 | 24 | 6 | 5 | 0 |
| `U_F5_NGINX_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` | 32 | 21 | 10 | 1 | 0 |
| `U_Google_Chrome_V2R11_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip` | 46 | 44 | 2 | 0 | 0 |
| `U_Kubernetes_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip` | 92 | 61 | 31 | 0 | 0 |
| `U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip` | 33 | 0 | 3 | 30 | 0 |
| `U_MOZ_Firefox_Windows_V6R8_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` | 33 | 32 | 1 | 0 | 0 |
| `U_MS_Defender_Antivirus_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV15-signed.zip` | 67 | 67 | 0 | 0 | 0 |
| `U_MS_DotNet_Framework_4-0_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV15-signed.zip` | 17 | 9 | 3 | 5 | 0 |
| `U_MS_Edge_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip` | 61 | 56 | 5 | 0 | 0 |
| `U_MS_Exchange_2019_Edge_Server_V2R2_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` | 68 | 53 | 13 | 2 | 0 |
| `U_MS_Exchange_2019_Mailbox_Server_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` | 66 | 50 | 15 | 1 | 0 |
| `U_MS_IE11_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` | 137 | 137 | 0 | 0 | 0 |
| `U_MS_IIS_10-0_Server_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` | 40 | 22 | 15 | 3 | 0 |
| `U_MS_IIS_10-0_Site_V2R14_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 44 | 26 | 11 | 7 | 0 |
| `U_MS_IIS_8-5_Server_V2R7_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` | 43 | 18 | 24 | 1 | 0 |
| `U_MS_IIS_8-5_Site_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` | 49 | 15 | 29 | 5 | 0 |
| `U_MS_Office_365_ProPlus_V3R8_STIG_SCAP_1-4_Benchmark-enhancedV11-signed.zip` | 139 | 138 | 1 | 0 | 0 |
| `U_MS_OneDrive_V2R4_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip` | 12 | 12 | 0 | 0 | 0 |
| `U_MS_SQL_Server_2016_Database_V3R4_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` | 23 | 0 | 0 | 0 | 23 |
| `U_MS_SQL_Server_2016_Instance_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV14-signed.zip` | 84 | 0 | 0 | 0 | 84 |
| `U_MS_SQL_Server_2022_Database_V1R2_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip` | 23 | 0 | 0 | 0 | 23 |
| `U_MS_SQL_Server_2022_Instance_V1R3_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip` | 79 | 0 | 0 | 0 | 79 |
| `U_MS_Windows_10_V3R7_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` | 267 | 225 | 12 | 30 | 0 |
| `U_MS_Windows_11_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` | 257 | 244 | 11 | 2 | 0 |
| `U_MS_Windows_2012_and_2012_R2_DC_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` | 364 | 210 | 96 | 58 | 0 |
| `U_MS_Windows_2012_and_2012_R2_MS_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` | 329 | 191 | 82 | 56 | 0 |
| `U_MS_Windows_Defender_Firewall_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV14-signed.zip` | 21 | 20 | 1 | 0 | 0 |
| `U_MS_Windows_Server_2016_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 272 | 198 | 28 | 46 | 0 |
| `U_MS_Windows_Server_2019_V3R9_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 282 | 252 | 27 | 3 | 0 |
| `U_MS_Windows_Server_2022_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 278 | 248 | 27 | 3 | 0 |
| `U_MS_Windows_Server_2025_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` | 291 | 258 | 30 | 3 | 0 |
| `U_MS_Windows_Server_DNS_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip` | 81 | 39 | 40 | 2 | 0 |
| `U_Oracle_Linux_7_V3R3_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip` | 243 | 169 | 72 | 2 | 0 |
| `U_Oracle_Linux_8_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 376 | 321 | 52 | 3 | 0 |
| `U_Oracle_Linux_9_V1R4_STIG_SCAP_1-4_Benchmark-enhancedV5-signed.zip` | 448 | 399 | 40 | 9 | 0 |
| `U_RHEL_7_V3R15_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 244 | 185 | 58 | 1 | 0 |
| `U_RHEL_8_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV22-signed.zip` | 369 | 329 | 32 | 8 | 0 |
| `U_RHEL_9_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` | 445 | 409 | 27 | 9 | 0 |
| `U_SLES_12_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip` | 210 | 119 | 89 | 2 | 0 |
| `U_SLES_15_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 218 | 134 | 83 | 1 | 0 |
| `U_SOL_11_SPARC_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` | 215 | 140 | 74 | 1 | 0 |
| `U_SOL_11_X86_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` | 214 | 140 | 73 | 1 | 0 |
| `U_TOSS_4_V2R7_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip` | 225 | 193 | 30 | 2 | 0 |

## Primary blocker root causes

| Category | Message | Rules |
|---|---|---:|
| `unsupported-capability` | unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test | 125 |
| `unsupported-construct` | XCCDF Value operator requires an explicit constraint adapter | 36 |
| `unsupported-construct` | multiple aggregation components need an approved collection expression | 30 |
| `unsupported-capability` | unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}wmi_test | 20 |
| `unsupported-capability` | unsupported object capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}wmi_object | 14 |
| `unsupported-construct` | ordered comparison expansion requires integer source datatype | 10 |
| `unsupported-capability` | unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}user_test | 8 |
| `unsupported-construct` | invalid original pattern-path recursion attributes | 7 |
| `unsupported-construct` | check-export source/Variable datatype mismatch | 2 |
| `unsupported-construct` | unsupported State field/namespace | 2 |
| `schema-semantic` | authoring/direct-slice/assessments/amazon-linux-2023-record-storage-facility-sv-274067-assessment.json: {'function': {'name': 'arithmetic', 'arguments': [{'values': {'object': 'partition-mount-point-equals-from-a-source-variable-object', 'field': 'block_size'}}, {'values': {'object': 'partition-mount-point-equals-from-a-source-variable-object', 'field': 'total_space'}}], 'options': {'arithmetic_operation': 'multiply'}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/amazon-linux-2023-ensure-user-ids-uids-sv-274160-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': 'interactive-users-object', 'field': 'user_id'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/ubuntu-operating-systems-maintenance-modes-sv-219147-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': {'capability': 'independent.textfilecontent', 'full_path': {'equals': '/boot/grub/grub.cfg'}, 'pattern': {'matches_regex': '^\\s*set\\s+superusers="(root)"\\s*$'}, 'instance': {'greater_than_or_equal': 1}, 'ignore_case': False, 'multiline': True, 'singleline': False, 'item_creation': 'all_object_elements_fullfilled', 'filesystem': 'all'}, 'field': 'subexpression'}}], 'options': {'delimiter': ' '}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/ubuntu-operating-systems-and-maintenance-sv-219148-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': {'capability': 'independent.textfilecontent', 'full_path': {'equals': '/boot/efi/EFI/ubuntu/grub.cfg'}, 'pattern': {'matches_regex': '^\\s*set\\s+superusers="(root)"\\s*$'}, 'instance': {'greater_than_or_equal': 1}, 'ignore_case': False, 'multiline': True, 'singleline': False, 'item_creation': 'all_object_elements_fullfilled', 'filesystem': 'all'}, 'field': 'subexpression'}}], 'options': {'delimiter': ' '}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/ubuntu-22-04-lts-uniquely-users-sv-260543-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': 'interactive-users-object', 'field': 'user_id'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/ubuntu-24-04-lts-uniquely-users-sv-270720-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': 'interactive-users-object', 'field': 'user_id'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/cisco-router-limit-number-defined-number-sv-215807-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': {'capability': 'iosxe.global', 'global_command': {'matches_regex': '^line vty \\d+'}}, 'field': 'global_command'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/cisco-router-enforce-on-control-policies-sv-215812-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': {'capability': 'iosxe.global', 'global_command': {'matches_regex': '^line vty \\d+'}}, 'field': 'global_command'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/cisco-router-terminate-of-inactivity-sv-215833-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': {'capability': 'iosxe.global', 'global_command': {'matches_regex': '^line con \\d+\|^line vty \\d+'}}, 'field': 'global_command'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/cisco-router-synchronize-time-sources-sv-215838-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': {'capability': 'iosxe.global', 'global_command': {'matches_regex': '^ntp[ \\t]+server[ \\t]+\\S+[ \\t]*'}}, 'field': 'global_command'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/cisco-router-use-at-least-access-sv-215854-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': {'capability': 'iosxe.global', 'global_command': {'matches_regex': '^line vty \\d+'}}, 'field': 'global_command'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/cisco-switch-limit-number-defined-number-sv-220518-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': {'capability': 'iosxe.global', 'global_command': {'matches_regex': '^line vty \\d+'}}, 'field': 'global_command'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/cisco-switch-enforce-on-control-policies-sv-220523-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': {'capability': 'iosxe.global', 'global_command': {'matches_regex': '^line vty \\d+'}}, 'field': 'global_command'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/cisco-switch-terminate-of-inactivity-sv-220544-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': {'capability': 'iosxe.global', 'global_command': {'matches_regex': '^line con \\d+\|^line vty \\d+'}}, 'field': 'global_command'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/cisco-switch-synchronize-time-sources-sv-220549-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': {'capability': 'iosxe.global', 'global_command': {'matches_regex': '^ntp[ \\t]+server[ \\t]+\\S+[ \\t]*'}}, 'field': 'global_command'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/cisco-switch-use-at-least-access-sv-220565-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': {'capability': 'iosxe.global', 'global_command': {'matches_regex': '^line vty \\d+'}}, 'field': 'global_command'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/cisco-router-limit-number-defined-number-sv-215662-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': {'capability': 'iosxe.global', 'global_command': {'matches_regex': '^line vty \\d+'}}, 'field': 'global_command'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/cisco-router-enforce-on-control-policies-sv-215667-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': {'capability': 'iosxe.global', 'global_command': {'matches_regex': '^line vty \\d+'}}, 'field': 'global_command'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/cisco-router-terminate-of-inactivity-sv-215688-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': {'capability': 'iosxe.global', 'global_command': {'matches_regex': '^line con \\d+\|^line vty \\d+'}}, 'field': 'global_command'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/cisco-router-synchronize-time-sources-sv-215693-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': {'capability': 'iosxe.global', 'global_command': {'matches_regex': '^ntp[ \\t]+server[ \\t]+\\S+[ \\t]*'}}, 'field': 'global_command'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/cisco-router-use-at-least-access-sv-215709-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': {'capability': 'iosxe.global', 'global_command': {'matches_regex': '^line vty \\d+'}}, 'field': 'global_command'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/cisco-switch-limit-number-defined-number-sv-220570-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': {'capability': 'iosxe.global', 'global_command': {'matches_regex': '^line vty \\d+'}}, 'field': 'global_command'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/cisco-switch-enforce-on-control-policies-sv-220575-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': {'capability': 'iosxe.global', 'global_command': {'matches_regex': '^line vty \\d+'}}, 'field': 'global_command'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/cisco-switch-terminate-of-inactivity-sv-220596-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': {'capability': 'iosxe.global', 'global_command': {'matches_regex': '^line con \\d+\|^line vty \\d+'}}, 'field': 'global_command'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/cisco-switch-synchronize-time-sources-sv-220601-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': {'capability': 'iosxe.global', 'global_command': {'matches_regex': '^ntp[ \\t]+server[ \\t]+\\S+[ \\t]*'}}, 'field': 'global_command'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/cisco-switch-use-at-least-access-sv-220617-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': {'capability': 'iosxe.global', 'global_command': {'matches_regex': '^line vty \\d+'}}, 'field': 'global_command'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `unsupported-capability` | state capability mismatch: oval:navy.navwar.niwcatlantic.scc.nginx:ste:27840004 | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/digital-signatures-assemblies-verified-sv-225223-assessment.json: {'hive': {'equals': 'local_machine'}, 'key': {'equals': 'SOFTWARE\\Microsoft\\StrongName\\Verification'}, 'name': {'matches_regex': '.*'}, 'traversal': {'max_depth': 'unlimited'}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/exchange-queue-database-partition-sv-259592-assessment.json: {'function': {'name': 'substring', 'arguments': [{'values': {'object': 'shellcommand-object-true-msiinstallpath-msiinstallpath-w-object', 'field': 'stdout_line'}}], 'options': {'substring_start': 1, 'substring_length': 1}}} is not valid under any of the given schemas | 1 |
| `unsupported-construct` | Variable cast outside bounded proof | 1 |
| `unsupported-capability` | state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.10.site:ste:21874102 | 1 |
| `unsupported-capability` | state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.10.site:ste:21874205 | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/idle-time-out-monitor-for-website-enabled-sv-218762-assessment.json: Native Variable expression: Variable time-in-int-hhmmss-used-to-be-hh-mm-ss-variable: declared/derived datatype conflict (['string'] vs integer) | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/iis-10-0-website-have-application-pool-sv-218771-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': 'the-iis-10-website-must-have-a-unique-application-pool-object', 'field': 'result'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/application-pools-rapid-0-website-managed-sv-218778-assessment.json: Native Variable expression: Variable time-in-int-hhmmss-used-to-be-hh-mm-ss-variable: declared/derived datatype conflict (['string'] vs integer) | 1 |
| `unsupported-capability` | state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.10.site:ste:21878101 | 1 |
| `unsupported-capability` | state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.8.5.site:ste:80 | 1 |
| `unsupported-capability` | state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.8.5.site:ste:93 | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/application-pools-rapid-5-website-managed-sv-214492-assessment.json: Native Variable expression: Variable time-in-int-hhmmss-used-to-be-hh-mm-ss-variable: declared/derived datatype conflict (['string'] vs integer) | 1 |
| `unsupported-capability` | state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.8.5.site:ste:180 | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/windows-dns-server-for-external-queries-sv-259341-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': {'capability': 'independent.shellcommand', 'shell': 'powershell', 'command': 'Get-DnsServerForwarder \| ForEach-Object {$_.IPAddress.IPAddressToString}', 'error_if_exit_status_not_0': False, 'error_if_stderr_exists': False}, 'field': 'stdout_line'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/windows-dns-server-s-ip-locally-on-server-sv-259374-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': 'the-list-of-online-network-adapter-interface-indexes-object', 'field': 'stdout_line'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `unsupported-construct` | Assessment Input function composition requires a supported typed expression | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/for-ol-8-systems-using-two-name-servers-sv-248634-assessment.json: {'function': {'name': 'count', 'arguments': [{'function': {'name': 'unique', 'arguments': [{'values': {'object': 'etc-resolv-conf-nameserver-entries-object', 'field': 'subexpression'}}], 'options': {}}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/ol-8-duplicate-user-ids-interactive-users-sv-248701-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': 'interactive-users-object', 'field': 'user_id'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/ol-9-allocate-audit-worth-of-audit-records-sv-271596-assessment.json: {'function': {'name': 'arithmetic', 'arguments': [{'values': {'object': 'partition-mount-point-equals-from-a-source-variable-object', 'field': 'block_size'}}, {'values': {'object': 'partition-mount-point-equals-from-a-source-variable-object', 'field': 'total_space'}}], 'options': {'arithmetic_operation': 'multiply'}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/ol-9-must-mount-tmp-with-the-nodev-option-sv-271653-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/ol-9-mount-var-log-with-nodev-option-sv-271657-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/ol-9-mount-var-log-with-noexec-option-sv-271658-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/ol-9-mount-var-log-with-nosuid-option-sv-271659-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/ol-9-mount-var-log-audit-with-nodev-option-sv-271660-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/ol-9-duplicate-user-ids-interactive-users-sv-271832-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': 'interactive-users-object', 'field': 'user_id'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/ol-9-groups-must-have-unique-group-id-gid-sv-271835-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': 'etc-group-gids-object', 'field': 'subexpression'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/ol-9-systems-using-domain-two-name-servers-sv-271861-assessment.json: {'function': {'name': 'count', 'arguments': [{'function': {'name': 'unique', 'arguments': [{'values': {'object': 'etc-resolv-conf-nameserver-entries-object', 'field': 'subexpression'}}], 'options': {}}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/for-rhel-8-systems-using-two-name-servers-sv-230316-assessment.json: {'function': {'name': 'count', 'arguments': [{'function': {'name': 'unique', 'arguments': [{'values': {'object': 'etc-resolv-conf-nameserver-entries-object', 'field': 'subexpression'}}], 'options': {}}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/rhel-8-duplicate-user-ids-users-sv-230371-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': 'interactive-users-object', 'field': 'user_id'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/rhel-8-must-mount-tmp-with-the-nodev-option-sv-230511-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/rhel-8-mount-var-log-with-nodev-option-sv-230514-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/rhel-8-mount-var-log-with-nosuid-option-sv-230515-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/rhel-8-mount-var-log-with-noexec-option-sv-230516-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/rhel-8-mount-var-log-with-nodev-option-sv-230517-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/rhel-9-must-mount-tmp-with-the-nodev-option-sv-257866-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/rhel-9-mount-var-log-with-nodev-option-sv-257870-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/rhel-9-mount-var-log-with-noexec-option-sv-257871-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/rhel-9-mount-var-log-with-nosuid-option-sv-257872-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/rhel-9-mount-var-log-with-nodev-option-sv-257873-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-filepath-s-s-s-s-s-s-instance-equals-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ','}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/rhel-9-systems-using-two-name-servers-sv-257948-assessment.json: {'function': {'name': 'count', 'arguments': [{'function': {'name': 'unique', 'arguments': [{'values': {'object': 'etc-resolv-conf-nameserver-entries-object', 'field': 'subexpression'}}], 'options': {}}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/rhel-9-duplicate-user-ids-users-sv-258045-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': 'interactive-users-object', 'field': 'user_id'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/rhel-9-groups-must-have-unique-group-id-gid-sv-258061-assessment.json: {'function': {'name': 'count', 'arguments': [{'values': {'object': 'etc-group-gids-object', 'field': 'subexpression'}}], 'options': {}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/rhel-9-allocate-audit-of-audit-records-sv-258155-assessment.json: {'function': {'name': 'arithmetic', 'arguments': [{'values': {'object': 'partition-mount-point-equals-from-a-source-variable-object', 'field': 'block_size'}}, {'values': {'object': 'partition-mount-point-equals-from-a-source-variable-object', 'field': 'total_space'}}], 'options': {'arithmetic_operation': 'multiply'}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/run-control-scripts-only-authorized-paths-sv-216301-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-object-than-or-equal-s-path-s-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ':'}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/run-control-scripts-only-authorized-paths-sv-216066-assessment.json: {'function': {'name': 'split', 'arguments': [{'values': {'object': 'textfilecontent54-object-than-or-equal-s-path-s-1-object', 'field': 'subexpression'}}], 'options': {'delimiter': ':'}}} is not valid under any of the given schemas | 1 |
| `schema-semantic` | authoring/direct-slice/assessments/for-toss-systems-using-two-name-servers-sv-252935-assessment.json: {'function': {'name': 'count', 'arguments': [{'function': {'name': 'unique', 'arguments': [{'values': {'object': 'etc-resolv-conf-nameserver-entries-object', 'field': 'subexpression'}}], 'options': {}}}], 'options': {}}} is not valid under any of the given schemas | 1 |

## Verification status

The ledger was rebuilt from the pinned source ZIPs with SQLEXT-dependent SQL benchmarks intentionally excluded. Source Rule IDs, check selection, source hashes, and provenance remain in `COMPLETE-LEDGER.json`. All automated Rules are **converted but unproved**; none is promoted by YAML/schema admission or compilation. This tools branch has no independent scanner/OVAL comparison or compiler qualification, so `automated_converted_proved` remains zero.
