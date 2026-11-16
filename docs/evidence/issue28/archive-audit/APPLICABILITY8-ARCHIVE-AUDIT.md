# Independent applicability.8 archive audit

Archive: `https://github.com/vanderpol/scap-ng-tools/releases/download/assessment-corpus-0.4.0-issue28-applicability.8/applicability.8.tar.gz`
SHA-256: `e164ba54ac99ed1ebc6d205205deedea311ad92abd3d83739073eb0751ae4125`

This is a read-only archive audit. It does not invoke the generator or claim scanner/runtime equivalence.

## Summary

- **PASS** — archive identity and hierarchy: published SHA-256 and safe archive structure verified
- **PASS** — SHA256SUMS and complete file discovery: 45426 entries checked against 45426 files
- **PASS** — exact pinned schema validation: 22648 native JSON documents and 22648 YAML documents validated; 129 metadata JSON files parsed separately
- **PASS** — JSON/YAML semantic equivalence and metadata: all native JSON/YAML pairs are semantically equal and both forms pass the exact pinned schemas; required metadata parsed
- **PASS** — shared Assessment normalization and dependency closure: 14648 package-local Assessments and 25527 nested references checked; zero unresolved refs/cycles
- **PASS** — Benchmark/Group/Rule applicability inheritance: all emitted Rule applicability includes its Benchmark conditions; no emitted Groups exist in the 0.4 direct-slice packages
- **PASS** — identity collisions and redundant wrappers: no package-local duplicate IDs, conflicting definitions, or one-child wrappers; 67 cross-package reused IDs retained as scope-qualified
- **PASS** — source traceability and disposition reconciliation: 8199 ledger Rule records and 4 evidence-only excluded packages reconciled
- **PASS** — representative RHEL/Windows/Oracle authoring files: RHEL 9, Windows 11, Windows Server 2025, and Oracle Linux 9 samples found and parsed
- **FAIL** — VS Code editor directory suitability: 1 editor discovery defect(s)

## Pins

- Source: `8c8e5dff860af6b1290ee9273a282db24278f8d5`
- Schema: `919732d4c570b521edf82196a7694dfd8c27fe50`
- Schema digest: `6bf2fa369fd7b9a0153899ac25109af3e3f9aa59c0f4aa6bb3be1aebd5b14fa0`
- Tools: `aaf3a420840d8a388ac0eb153e05cd54b9e7741c`

## Actual inventory

- Emitted package directories: **59**
- Evidence package directories: **63**
- Native JSON documents: **22648**
- Native YAML documents: **22648**
- Assessment JSON/YAML pairs: **14648**
- SHA256SUMS entries: **45426**

## Evidence-only excluded packages

- `41-U_MS_SQL_Server_2016_Database_V3R4_STIG_SCAP_1-4_Benchmark-enhancedV13-signed`
- `42-U_MS_SQL_Server_2016_Instance_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV14-signed`
- `43-U_MS_SQL_Server_2022_Database_V1R2_STIG_SCAP_1-4_Benchmark-enhancedV8-signed`
- `44-U_MS_SQL_Server_2022_Instance_V1R3_STIG_SCAP_1-4_Benchmark-enhancedV8-signed`

These four SQL/SQLEXT benchmarks have evidence receipts but no emitted authoring package, consistent with their `intentionally_excluded_sqlext` ledger scope.

## Shared Assessment graph and identity audit

- Package-local Assessment definitions: **14648**
- Package-local conditions: **243**
- Nested Assessment references scanned: **25527**
- Cross-package reused IDs: **67**; these are package-scoped and are reported, not merged.
- Cross-package same-ID differing bodies: **30**. These are not package-local collisions, but an editor must preserve package scope when indexing the corpus.

## Representative authoring files

- **RHEL 9:** `documents/58-U_RHEL_9_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed/authoring/direct-slice/assessments/all-rhel-9-interactive-exists-sv-258048-manual-0-assessment.yaml` — `all-rhel-9-interactive-exists-sv-258048-manual-0-assessment` — manual — All RHEL 9 interactive users must have a primary group that exists.
- **Windows 11:** `documents/46-U_MS_Windows_11_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV18-signed/authoring/direct-slice/assessments/access-credential-manager-or-accounts-sv-253479-assessment.yaml` — `access-credential-manager-or-accounts-sv-253479-assessment` — automated — The "Access Credential Manager as a trusted caller" user right must not be assigned to any groups or accounts.
- **Windows Server 2025:** `documents/51-U_MS_Windows_Server_2025_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV1-signed/authoring/direct-slice/assessments/outdated-or-unused-or-disabled-sv-278003-manual-assessment.yaml` — `outdated-or-unused-or-disabled-sv-278003-manual-assessment` — manual — Outdated or unused accounts on Windows Server 2025 must be removed or disabled.
- **Oracle Linux 9:** `documents/55-U_Oracle_Linux_9_V1R4_STIG_SCAP_1-4_Benchmark-enhancedV5-signed/authoring/direct-slice/assessments/ol-9-able-directly-is-removed-sv-271690-manual-0-assessment.yaml` — `ol-9-able-directly-is-removed-sv-271690-manual-0-assessment` — manual — OL 9 must be able to directly initiate a session lock for all connection types using smart card when the smart card is removed.

## Defects and limitations

- `documents/01-U_Active_Directory_Domain_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV2-signed/authoring/direct-slice/assessments/access-need-know-community-of-interest-sv-243481-assessment.yaml` — 14648 YAML Assessment files use *-assessment.yaml, but the editor custom editor pattern is **/*.assessment.yaml; direct SCAP-NG custom-editor discovery will miss them

### Editor discovery correction (not applied)

The archive uses `*-assessment.yaml`, while the current VS Code custom editor selector is `**/*.assessment.yaml`. The smallest corrective change is to align that selector with the published filename convention (or republish under a new immutable archive); this audit did not modify either repository or archive.

The machine-readable report contains the complete extracted directory and file inventory under `hierarchy.directories` and `hierarchy.files`.

## Scope boundary

All native authoring JSON/YAML documents passed the exact pinned Draft 2020-12 schemas. Archive metadata/evidence JSON has no applicable native root schema and was parsed and inventory-checked separately. This is structural validation only; it is not evidence of scanner execution or runtime equivalence.
