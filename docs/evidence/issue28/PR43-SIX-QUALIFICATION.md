# Tools PR #43: six-stream qualification evidence

Status: **PASS**

PASS means source-preserving conversion and current-schema authoring validation only; no independent OVAL semantic proof or scanner qualification is claimed.

## Pinned contracts

- Tools commit: `1de1798`
- Schema commit: `f7e5e845d21e3a38ec5dc5ec04228b763acd9c5b`
- Schema version: `0.4.0`
- Schema snapshot aggregate SHA-256: `63a61b3eb0ca95790721699f5e63b6f5a16b146660b9545a437519b508351db5`
- Schema snapshot root/ref counts: 35/673
- Unapproved schema PR #27: **not adopted**
- Unsupported OVAL functions: remain blocked; no proof promotion

## Per-Benchmark results

| Benchmark | Rules | Converted | Blocked | Native docs | OCIL/manual source Rules retained | Stage repeat | Packager repeat | Result |
|---|---:|---:|---:|---:|---:|---|---|---|
| `U_Apache_Server_2-4_UNIX_Server_V3R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed` | 45 | 9 | 36 | 40 | 45 | `8d34b31210a8` = `8d34b31210a8` | `14404d872350` = `14404d872350` | **PASS** |
| `U_MS_Windows_11_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV18-signed` | 257 | 220 | 37 | 884 | 257 | `b1074504ec4b` = `b1074504ec4b` | `0c1d2c8b1913` = `0c1d2c8b1913` | **PASS** |
| `U_MS_Windows_Server_2025_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV1-signed` | 291 | 247 | 44 | 992 | 291 | `c65c3a9d1a44` = `c65c3a9d1a44` | `9bb6d77d0584` = `9bb6d77d0584` | **PASS** |
| `U_MS_Windows_Server_DNS_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV8-signed` | 81 | 37 | 44 | 152 | 81 | `3275d0c23e0b` = `3275d0c23e0b` | `da0dd9056ea7` = `da0dd9056ea7` | **PASS** |
| `U_Oracle_Linux_9_V1R4_STIG_SCAP_1-4_Benchmark-enhancedV5-signed` | 448 | 290 | 158 | 1164 | 448 | `131ed3b826e4` = `131ed3b826e4` | `5bbba1eb198b` = `5bbba1eb198b` | **PASS** |
| `U_RHEL_9_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed` | 445 | 302 | 143 | 1212 | 445 | `47a1c293c11e` = `47a1c293c11e` | `018f15a3a5c8` = `018f15a3a5c8` | **PASS** |

## Pinned source hashes

| Benchmark | Source ZIP SHA-256 | Bytes | Git blob SHA |
|---|---|---:|---|
| `U_Apache_Server_2-4_UNIX_Server_V3R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed` | `8894123788ba415373625eaecdbbd834f190668697803c3319393c11889f1b80` | 66035 | `01b08ac54811cc190c4b677f9cf3d26613e3a4b7` |
| `U_MS_Windows_11_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV18-signed` | `e4b8d55b58aa80124bd0974977af4c7f7bde35c748e2940e02857419292d8c3d` | 209207 | `712cc3176b1e44616aaf2f3ba5e62b299ad0643c` |
| `U_MS_Windows_Server_2025_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV1-signed` | `2f46264b5fa21c8a033236121794ebe372314bf7458dac0aca4f81179fe7ece0` | 254194 | `f6ba90413cd8a6ab3f9f5acc82603d9b52aca9cf` |
| `U_MS_Windows_Server_DNS_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV8-signed` | `f674b67e74acbd3037093d50e33dc20765bd9d45a6c9ed2be5d463d009a6c6b8` | 103675 | `eca2b802a66f5ba103bd180db5f7ec8279e00709` |
| `U_Oracle_Linux_9_V1R4_STIG_SCAP_1-4_Benchmark-enhancedV5-signed` | `6733abd693380b43b2350c2692775e4ff902f895f16899db97b34fecf7fba74d` | 372511 | `4250e3eae3b1a15ad5db270b1f28db71007c64ff` |
| `U_RHEL_9_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed` | `70aa6a16221df2c53b094b11b48b16aca1f6d7147c11123b655659ca7711dbb5` | 393068 | `349b8e162696717079bd05139afe30d789c80f6a` |

## Source and provenance checks

Each stream passed: pinned source ZIP SHA-256; original XCCDF Rule ID and count preservation; exact retention of the source archive and XML datastream members; OCIL Rule ID retention; current frozen-schema validation of generated JSON/YAML; packager metadata pin checks; and deterministic repeated generation. The packager remains a source-preserving automated-subset draft and does not fabricate native manual Assessments.

## Unsupported function hold

| Benchmark | Unsupported function blocker rows |
|---|---|
| `U_Apache_Server_2-4_UNIX_Server_V3R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed` | none observed |
| `U_MS_Windows_11_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV18-signed` | none observed |
| `U_MS_Windows_Server_2025_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV1-signed` | substring: 11 |
| `U_MS_Windows_Server_DNS_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV8-signed` | count: 13 |
| `U_Oracle_Linux_9_V1R4_STIG_SCAP_1-4_Benchmark-enhancedV5-signed` | arithmetic: 3, count: 29, split: 35 |
| `U_RHEL_9_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed` | arithmetic: 3, count: 29, split: 35 |

## Totals

- Source Rules: **1567**
- Automated converted, authoring/schema validated, unproved: **1105**
- Blocked: **462**
- Native JSON/YAML documents validated (stage A): **4444**
- Source OCIL/manual Rule IDs retained: **1567**
- Independently proved: **0 claimed**

## Test receipts

- Fixture restore: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`.
- Fixture-backed converter suite: **60 passed, 0 failed, 0 skipped** (receipt: `/tmp/pr43-full-final-qualified2.txt`; rerun: 60 passed, 39 subtests passed).
- Six Stage A conversions: **6/6 return code 0**, each converter receipt reports `schema_validated: true`.
- Stage A repeated conversion: **6/6 byte/tree-identical**.
- Recovered source-preserving packager and repeat: **6/6 pass; byte/tree-identical**.

## Qualification boundary

This is not independent OVAL equivalence proof, compiler/scanner qualification, or a claim that blocked Rules are converted. The six-stream gate passed. The all-65 run is being evaluated separately; no goldens, merges, releases, or VS Code files were changed.
