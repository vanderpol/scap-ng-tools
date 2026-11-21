# Prospective canonical PR #77/#79 qualification

This is a **structural-only review receipt** for unmerged canonical schema PRs. It is not a production conversion result or semantic/runtime equivalence claim.

- Tools: `0311226e`
- Canonical base: `5ee55288`
- PR #77: `e96aac31` (Windows Registry traversal)
- PR #79: `44c53040` (typed Input expression)

| Case | Result | Tests |
|---|---|---:|
| `def:38` Windows Registry | structural conversion only | 15 |
| `def:562` external Variable | remains blocked | 18 |
| `def:729` Registry effective rights | remains blocked | 5 |
| Windows NTUSER `def:38` | remains blocked | 20 |

PR #77 would potentially remove one Definition / 15 Test blockers after canonical semantic-pack regeneration, converter pin coordination and runtime qualification. PR #79 alone does not resolve standalone OVAL external-variable binding.

See the machine receipt for exact source hashes, schema file hashes, diagnostics and reproducibility.
