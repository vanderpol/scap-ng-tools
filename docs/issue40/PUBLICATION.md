# Current-native publication gate — Tools #40

**Review implementation; not deployed completion.** The [exact-main baseline](publication-baseline.json) initially identified 217 unguarded Research upload/write steps and one Evidence release step. The [expanded AST/heredoc audit](publication-expanded-baseline.json) identifies **227 Research steps: 186 uploads and 41 direct writers**, including ten missed by the initial shell-only pass. Canonical has no native-content publisher. Integrations are separate review changes. Four permission-policy queries returned HTTP 403; ten active Research Actions records have no file on current main. These remain explicit blockers until enforcement is verified.

## Contract and trust boundary

`scapng-convert-v04` is the only supported converter. `scapng-publish-v04` is its admission boundary, not a second converter. The proposed policy pins Tools `f97ff187460f52da78bd16f5009f7d182664812b`, distribution `scap-ng-tools 0.0.0`, the exact source fingerprint and `scapng-convert-v04 = scap_ng_tools.converter.direct04:main`. This is a development source distribution, not a released wheel or product release.

The gate checks the real clean checkout and copies pinned Git blobs into a fresh isolated execution tree without cached bytecode. It runs that approved facade itself. No caller-selected executable, renamed wrapper or manifest producer claim supplies execution authority. Flat schema revision must be `6012ae2` or byte-equivalent `f7e5e84`, with whole-family digest `63a61b3eb0ca95790721699f5e63b6f5a16b146660b9545a437519b508351db5`.

The closed manifest records distribution/version, entrypoint, source commit and clean status, executed source fingerprint, interpreter version/binary hash, schema commit/digest, original repository/commit/path/hash, actual file hashes/sizes, explicit `schema_validated: true` / `final_serializations_validated: true` status, and qualification tier. Original input bytes must match the immutable source blob. Repository URI is bound by the approved revision catalog; an observed origin must agree. Imported Git objects without a remote explicitly record `origin_observed: false`. None of this authenticates a publisher.

Admission checks actual JSON/YAML, duplicate keys, counterpart equality, native schema validation and the exact file set. It then **reproduces every payload byte through the pinned current converter**, including trace/scope sidecars. Rehashing a forged manifest cannot authorize historical or changed content. The admitted ZIP is written only from checked byte buffers, preventing later filesystem substitution. Failures exit nonzero and produce no qualified archive. The shared current-publication action uploads only this admitted ZIP and defaults to dry-run.

Hashes alone are not signatures or proof of an earlier process. Admission establishes reproducible current authoring **now**, under trusted gate code, runner/interpreter/dependencies and sink configuration. It cannot stop an administrator bypassing the controlled sink. Server permission/environment restrictions and old-ref execution need separate evidence; inaccessible settings and unguarded refs remain blockers. No repository-wide completion is claimed.

## Qualification tiers

| Tier | Meaning | Gate treatment |
| --- | --- | --- |
| Schema-valid | Actual content satisfies the pinned structural schema | Required; not runtime proof |
| Converted-unverified | Generated authoring with source provenance | Retained on current output |
| Authoring-validated | Approved current converter, pinned inputs, final bytes and reproducible admission | Only admitted tier |
| Source-proved | Independent proof of stated original-source obligations | Never inferred; promotion rejected |
| RI-executed | Actual named execution with immutable content/evidence/evaluator | Never inferred; promotion rejected |
| Scanner-equivalent | Qualified independent differential evidence in the claimed domain | Never inferred; promotion rejected |

Compilation, old green workflows, static proof counts and schema-version strings cannot raise a tier. Full-65 completeness, proof transfer, scanner-equivalence and release-readiness claims are rejected.

## Supported facade modes

| Request mode | Existing converter invocation | Scope |
| --- | --- | --- |
| `focused` | Repeatable `--rule ID` | Explicit source Rules |
| `benchmark` | `--all-rules` | `selection: automatic_subset`; blocked/manual cases stay in accounting |
| `oval-definition` | `--oval-definition ID` | Complete original Definition, Tests, Variables and criteria |

No qualified full-65 reproduction exists here. `full-65` and `full_65_complete: true` fail closed. [Historical preservation](historical-preservation.json) keeps the 65-builder `build_v04_full_draft.py@a08c9be` and normalization `scap_ng_library_cli.py export-draft@03ddc6b` distinct from the later obsolete-Require Variable script at `fc62031`. Current production output did **not** have that Require defect. Old artifacts/proofs are unchanged and are not retrospectively promoted.

## Commands and maintenance

Dependencies: Python 3.11+, existing Tools dependencies, Git, and exact offline producer/schema/source checkouts. The gate fetches no input or schema.

Example `request.json`:

```json
{"mode":"oval-definition","source_commit":"e3538595c5083b9c34d937a81d319234df9bbfaa","source_path":"SCAP_1.4/OVAL_Test_Content/agnostic/oval-def_constant_variable.xml","source_sha256":"57113e1d5991bec0c7cee30d2789ecf9bff5223d2f2ab78900098c187a716e91","selection":"oval:org.mitre.oval.test:def:92"}
```

```sh
scapng-publish-v04 prepare --producer-root /path/to/tools-at-f97ff18 \
  --schema-root /path/to/approved-schema --source-root /path/to/Self-Assertion \
  --request request.json --output candidate
scapng-publish-v04 admit --producer-root /path/to/tools-at-f97ff18 \
  --schema-root /path/to/approved-schema --source-root /path/to/Self-Assertion \
  --candidate candidate --output CURRENT_NATIVE_AUTHORING_VALIDATED.zip
```

For focused/benchmark modes use the approved NIWC revision `8c8e5dff860af6b1290ee9273a282db24278f8d5`, original archive path/hash, and Rule list or `automatic_subset`. New producer/schema/source revisions or tiers require reviewed policy edits; no CLI override exists.

Historical uploads use shared `historical-upload`: copied/hashed selected bytes, unchanged relative payload paths, forced `HISTORICAL_DRAFT_UNQUALIFIED-…` artifact names. A companion downloader restores original aggregation directory names. Receipts stay outside payloads so proof readers do not consume invented records. Historical content has no current admission manifest. Direct legacy release/Git writes are denied through the common gate; old bodies and tags remain preserved.

See the [integration PRs, safe dependency order, and owner/admin decision packet](INTEGRATION.md).

## Evidence and integration limits

The required flat-schema CI lane supplies every fixture; missing required publication fixtures fail. Tests execute actual converter → serialize → parse/schema validate → reproduce → admit ZIP dry-run. Negatives include an **actual public historical Variable replay**, obsolete Require, old/renamed producers, dirty/unapproved checkout, wrong schema digest, missing provenance, post-validation mutation, duplicate YAML keys, JSON/YAML mismatch, swapped schema-valid bytes with rehashed manifests, and invalid tier/coverage promotion. Failures must be nonzero without publication. Existing goldens and frozen schema bytes remain unchanged. CI also runs the actual shared publication action in dry-run mode, with no artifact upload retries.

The structured workflow/AST inventory is evidence and a tripwire, not admission. Runtime calls must guard actual sinks. Cross-repository integration, exact-head CI, server policy and historical-ref controls must be verified before claiming complete coverage. Unknown, inaccessible and unguarded paths remain blockers.

The final current-admission manifest requires both explicit validation status flags; missing/false flags reject. The pinned historical actions at `053eeeb` retain the same sealer/denial behavior and do not issue current qualification. Current admission code is reviewed/tested at the Tools PR head; old-ref current-admission authority remains part of the server-policy blocker.
