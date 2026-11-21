# Full OVAL Self-Assertion conversion replay — run 3

This is a deterministic authoring/conversion receipt for the pinned 144-file corpus. It is not runtime execution, expected-result validation, or independent OVAL equivalence proof.

## Pins

- Source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`
- OVAL schema: `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`
- SCAP-NG: `5ee55288b369da26f308f40813e545b78dff2753` (0.4.1; schema family `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`)
- Tools converter: `40c8c9ca3c00dc546df60b186f040557c102eba4`

## Baseline result

| Scope | Total | Converted (schema-valid, unverified) | Blocked | Owner-excluded |
|---|---:|---:|---:|---:|
| Definitions | 168 | 150 | 16 | 2 |
| Tests | 803 | 688 | 113 | 2 |

All 803 source Tests reconcile by `(source_path, test_id)` with transitive Definition ownership. All 150 converted Definitions passed independent native JSON Schema and JSON/YAML read-back validation. Scanner execution is `not_run`.

## Family results — Definitions

| Family | Total | Converted | Blocked | Excluded |
|---|---:|---:|---:|---:|
| agnostic | 47 | 46 | 1 | 0 |
| aix | 2 | 0 | 0 | 2 |
| asa | 2 | 2 | 0 | 0 |
| ios | 11 | 10 | 1 | 0 |
| iosxe | 11 | 11 | 0 | 0 |
| junos | 2 | 1 | 1 | 0 |
| linux | 16 | 16 | 0 | 0 |
| macos | 20 | 17 | 3 | 0 |
| panos | 2 | 2 | 0 | 0 |
| solaris | 6 | 4 | 2 | 0 |
| unix | 13 | 12 | 1 | 0 |
| windows | 36 | 29 | 7 | 0 |

## Family results — Tests

| Family | Total | Converted | Blocked | Excluded |
|---|---:|---:|---:|---:|
| agnostic | 328 | 310 | 18 | 0 |
| aix | 2 | 0 | 0 | 2 |
| asa | 2 | 2 | 0 | 0 |
| ios | 16 | 12 | 4 | 0 |
| iosxe | 17 | 17 | 0 | 0 |
| junos | 2 | 1 | 1 | 0 |
| linux | 62 | 62 | 0 | 0 |
| macos | 43 | 34 | 9 | 0 |
| panos | 2 | 2 | 0 | 0 |
| solaris | 21 | 12 | 9 | 0 |
| unix | 72 | 60 | 12 | 0 |
| windows | 236 | 176 | 60 | 0 |

## Hold categories

| Category | Definitions | Tests | Meaning |
|---|---:|---:|---|
| `canonical_input_constraint_hold` | 1 | 18 | Valid external Variables require a canonical Input/restriction binding; no source values were fabricated. |
| `converter_failure` | 2 | 12 | Converter semantic/typing path needs a generic correction. |
| `deprecated_source_construct` | 4 | 21 | OVAL 5.12.3-deprecated source behavior remains an explicit hold. |
| `schema_or_validation_failure` | 2 | 35 | Generated native form is rejected by the pinned 0.4.1 schema/semantic admission. |
| `source_typed_literal_invalid` | 2 | 8 | Source literal violates the converter’s typed/policy contract. |
| `unmapped_source_test` | 0 | 1 | Source Test is not referenced by a Definition criterion. |
| `unsupported` | 5 | 18 | No admitted native mapping; not silently substituted. |

## Important source dispositions

- UNIX upward recursion is a source defect, not a SCAP-NG feature request. PR #16 removes only `tst:466`/`obj:577`; valid downward recursion remains.
- UNIX `tst:483` was a valid orphan caused by a commented-out Definition criterion. PR #17 activates it; focused conversion succeeds.
- Solaris `package_test` and `package511_test` are deprecated in OVAL 5.12.3. PR #15 removes those legacy witnesses from the corrected corpus; this is not conversion success.
- Windows `ntuser`/`registry` failures use valid downward traversal and remain a converter/schema-pack integration hold; no source rewrite is proposed.
- Agnostic external Variable restrictions remain a canonical Input contract hold; PR #14 corrects misleading float comments but does not mask the hold.

## Source correction PRs

See the machine-readable `source_correction_prs` list in the JSON receipt for exact heads, categories and focused effects. The earlier projection is superseded by the observed candidate overlay replay in [`full-self-assertion-conversion-20261119-candidate-all-fixes.json`](full-self-assertion-conversion-20261119-candidate-all-fixes.json). It is still not a merged-source qualification result: the candidate cherry-picked open PR heads #5–#17 locally.

## Reproduction

Use the command recorded in the JSON receipt with the pinned source checkout and schema snapshot. The full generated output is external evidence at `/tmp/issue83-full-conversion-run3-179511`; only this compact receipt is committed.
