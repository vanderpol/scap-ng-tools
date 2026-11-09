# Issue #28 PR integration audit and failure matrix

**Status: `UNQUALIFIED_RECOVERY_ONLY`; no merge, rebase, golden update, or semantic promotion.**

## Test result

- 49 full fixture-backed tests ran with the VM schema/source inputs.
- 11 failures and 4 expected skips.
- The 11 failures reproduce with `jsonschema 4.26.0`, `referencing`, and `PyYAML 6.0.3`.
- A 65-benchmark recovery-ledger run completed: **8,892 Rules = 6,524 automated + 1,581 manual + 578 blocked + 209 SQLEXT excluded**. This is a candidate ledger only; it did not independently prove semantics or validate every emitted document.

## Failure classification

| ID | Fixture/test | Classification | Root cause |
|---|---|---|---|
| F01 | Windows Server 2025 / `test_535_rules_preserve_admission_and_regenerated_document_hashes` | **regression** | Default conversion content and counts are unchanged, but recovery metadata is emitted even when all recovery flags are false. Intended metadata improvement is incorrectly applied to the historical default path. |
| F02 | Active Directory Domain / `test_535_rules_preserve_admission_and_regenerated_document_hashes` | **regression** | Same root cause as F01; no native Assessment content or Rule status changed. |
| F03 | Amazon Linux 2023 / `test_535_rules_preserve_admission_and_regenerated_document_hashes` | **regression** | Same root cause as F01; source accounting remains 187 Rules, 118 converted, 69 blocked. |
| F04 | Windows Defender Firewall / `test_535_rules_preserve_admission_and_regenerated_document_hashes` | **regression** | Same root cause as F01; source accounting remains 21 blocked and no native documents. |
| F05 | aggregate / `test_535_rules_preserve_admission_and_regenerated_document_hashes` | **cascade** | Not an independent conversion difference. Each subtest fails before its totals counters are incremented, so the final aggregate assertion observes zero. |
| F06 | Active Directory Domain / `test_cli_exact_common_bytes_match_owner_amended_v04_baseline` | **regression** | All native JSON/YAML files are byte-identical to current main. The aggregate CLI digest includes changed metadata files, so this is the same default-path provenance regression, not a semantic content difference. |
| F07 | Windows Server 2025 / `test_cli_inventory_has_no_native_assessment_or_proof` | **regression** | Inventory still emits zero native documents and preserves the same Rule count; only unconditional recovery/scope metadata differs. |
| F08 | Windows Server 2025 / `test_full_benchmark_inventories_match_pinned_original` | **regression** | Inventory identity and source hashes remain unchanged; default trace metadata is not backward-compatible. |
| F09 | Active Directory Domain / `test_full_benchmark_inventories_match_pinned_original` | **regression** | Same root cause as F08. |
| F10 | Amazon Linux 2023 / `test_full_benchmark_inventories_match_pinned_original` | **regression** | Same root cause as F08. |
| F11 | Windows Defender Firewall / `test_full_benchmark_inventories_match_pinned_original` | **regression** | Same root cause as F08; no source or native semantic drift observed. |

The current-main golden values are correct: running the same four fixtures on `c5f5b215000a1f9149ed56541320da5d7918c94a` reproduces the expected hashes. Therefore none of the 11 is classified as a stale golden.

## Code comparison

| Area | PR #42 | PR #33 | PR #38/#39/#41 | Integration consequence |
|---|---|---|---|---|
| Public facade (`direct04.py`) | Adds recovery flags and removes no-op default distinction | Adds broad recovery flags and candidate-ledger modes | #38 adds final JSON/YAML round-trip validation and converter provenance; #39 adds standalone OVAL Definition path | Keep #38/#39 facade gates; port recovery flags without dropping serialization/provenance checks. |
| Runtime converter | OCIL parser/manual lowering plus existing #31 recovery | Adds functions, identity, nil/absence, WMI, float, datatype, and ledger recovery | #39 reuses runtime for standalone Variables | Use #33 functional baseline; port #42 OCIL extraction into one canonical manual adapter. |
| Source selection | Four-value `automated_check` with local OCIL parsing | OVAL-preferred selection plus `manual04.py` alternatives | Later stacks assume the production facade | Reconcile to one selection API; do not retain two manual grammars. |
| Manual Assessment | `ocil-choice` with parsed questionnaire choices/outcomes | `manual04.py` bounded `ocil-manual` projection without parsing questionnaire graph | No competing manual contract in #38/#39/#41 | Preserve source parsing, but emit one owner-approved native manual shape. |
| Function grammar | No PR #33 function envelope | Count/arithmetic/split/substring and broader function contract | #39 standalone Variable conversion depends on shared runtime | Do not cherry-pick PR #42 runtime over #33; resolve at one runtime baseline. |
| Publication/authority | Not present | Not present | #41 fail-closed publication gate; #38 authority gate | Integrate last, after converter/provenance contracts stabilize. |

## Default-path fix required before integration

PR #42 unconditionally changes `trace.scope`, `coverage.scope`, and adds `coverage.recovery`, even when `native_recovery=False`, `recover_manual=False`, and `exclude_sqlext=False`. The integration patch must preserve current-main bytes for that default path and emit recovery metadata only when an explicit recovery mode is selected. Do not update historical goldens.

## Recommended integration order

1. Keep PR #42 as a preservation donor; do not merge it wholesale.
2. Freeze the canonical schema decision and repin the semantic pack (`scap-ng#27` candidate `919732d` if approved).
3. Establish PR #38 as the single production-facade/serialization/provenance authority.
4. Layer PR #39 standalone Variable support without replacing #38 gates.
5. Port PR #33 recovery features onto that authority baseline, retaining its function/WMI/identity/ledger work and resolving the schema pin.
6. Port PR #42’s source-only full-65 packager and richer OCIL source extraction; parameterize VM paths and keep generated corpora external.
7. Integrate PR #41 publication admission last.
8. Re-run default four-fixture byte parity, explicit recovery deltas, then the six-stream and 65-stream packager gates.

## Nov. 5 packager reuse

Reuse `build_current_draft.py`, `validate_stage_a.py`, source pin verification, Rule XML preservation, file manifests, and repeat-run comparison. Do not reuse its hardcoded `/tmp`/absolute VM paths or historical compiler/proof imports. The packager must call the final public facade and preserve separate structural-DRAFT, compile, proof, and scanner statuses.
