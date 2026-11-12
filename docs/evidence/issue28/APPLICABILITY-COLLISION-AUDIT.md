# Applicability identity collision audit

This audit uses the pinned source checkout `8c8e5dff860af6b1290ee9273a282db24278f8d5` and the published `assessment-corpus-0.4.0-issue28-applicability.7` archive. Assessment and condition identities are package-scoped; reuse between distinct benchmark packages is reported but is not a conflict.

| Scope | Count | Conflicts |
|---|---:|---:|
| Source benchmarks scanned | 63 | 0 |
| Unique source CPE platform IDs | 93 | 0 duplicate IDs within a benchmark |
| Published benchmark packages | 59 | 0 condition conflicts |
| Published condition IDs | 243 | 0 |
| Published Assessment IDs | 14,648 | 0 |

There are 37 cross-benchmark source platform-ID reuses and cross-package generated-ID reuses. These are expected package-local identities; all repeated definitions were byte/semantic consistent within their package. No conflicting source platform, generated condition, or Assessment identity was found.

The machine-readable result is `APPLICABILITY-COLLISION-AUDIT.json`. This is structural identity evidence only and does not establish scanner/runtime equivalence.
