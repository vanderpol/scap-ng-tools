# Canonical SCAP-NG 0.4 contract coordination

The converter does not claim equivalence from an inactive or mismatched schema
candidate. Two canonical-side branches were inspected against the pinned
Issue #28 schema snapshot:

| Contract | Canonical reference | Scope | Tools result |
|---|---|---|---|
| Binary32 comparisons | `da4c48dfc60dc96a46e7b85425f70fb8f301a0b1` | Exact finite IEEE-754 binary32 comparison contract | Converter recovery is enabled only in `native_recovery`; scanner/compiler proof remains unproved. |
| Native functions | `246a8d37cc54875386768a7d76b60a6f9c01d013` | Owner-directed `arithmetic`, `split`, and `substring` active-schema amendment; count/unique/merge are not in this amendment | Candidate syntax and semantic validation are implemented, but the branch has 143 frozen JSON documents while this tools snapshot requires 145. `FrozenSchemaSnapshot` rejects it; no output is promoted against it. |

The active pinned schema remains the authority for the 65-benchmark ledger. It
rejects canonical function calls in `Assessment.variables`, so `count`,
multi-component `unique`/`merge`, and the recovered arithmetic/split/substring
forms remain unproved or blocked rather than being admitted through a schema
override. No hidden compatibility syntax or silent coercion is used.
