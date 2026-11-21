# Self-Assertion candidate overlay replay — all open source corrections

This is a **candidate overlay**, not the pinned baseline and not a merge claim. It cherry-picks open Self-Assertion PR heads #5–#17 onto `e3538595c5083b9c34d937a81d319234df9bbfaa` and replays the production converter.

## Exact pins

- Candidate source commit: `da25e94d3665bfc1bb93adab56965b0a8e46b677`
- OVAL schema: `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`
- SCAP-NG 0.4.1: `5ee55288b369da26f308f40813e545b78dff2753`; schema family `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`
- Tools converter: `40c8c9ca3c00dc546df60b186f040557c102eba4`

## Observed candidate result

| Scope | Total | Converted/schema-valid/unverified | Blocked | Owner-excluded |
|---|---:|---:|---:|---:|
| Definitions | 166 | 158 | 6 | 2 |
| Tests | 791 | 726 | 63 | 2 |

The candidate denominator is smaller because PR #15 removes deprecated Solaris witnesses, PR #11 removes two deprecated Windows group-behavior Tests, and PR #16 removes the deprecated upward-recursion Test. These are source removals, not converted successes.

## Remaining holds

- **Agnostic:** 18 Tests / 1 Definition — external Variable/Input constraint contract.
- **Windows:** 40 Tests / 3 Definitions — valid downward NTUSER/Registry/regkey traversal rejected by the pinned active 0.4.1 schema admission.
- **iOS:** 4 Tests / 1 Definition — unsupported `version55_test`.
- **Junos:** 1 Test / 1 Definition — unsupported `xml_config_test`.

Linux has 62/62 converted Tests and UNIX has 71/71 converted Tests in this candidate. No runtime or independent OVAL equivalence is claimed.

The machine-readable receipt includes per-family results, source IDs, exact source hashes, blocker diagnostics and output artifact hashes.
