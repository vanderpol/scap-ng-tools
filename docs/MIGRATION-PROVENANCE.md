# Copy-first migration record — 2026-11-02

Status: **initial import for review; no cutover, source deletion or release**.

The owner authorized a safe, staged cleanup after the 0.4 schema-family freeze.
The source repository `vanderpol/scap-ng` retained its original files and current
versioned schemas. Its freeze merge is `1401c2851516e1af230231abe47a40419bca3dc1`,
followed by the Apache-2.0 license commit `d12a644f4607cdc9c9ada50e3a96d4fd0060c6d9`.

| Source path in `scap-ng` | Destination | SHA-256 of file bytes |
| --- | --- | --- |
| `tools/scap_ng_library/names.py` | `src/scap_ng_tools/authoring/names.py` | `49773328435e486ca46d09e8a694f17d29b00d61e05cf2ab376b1604eefcdbe5` |
| `tools/scap_ng_library/records.py` | `src/scap_ng_tools/authoring/records.py` | `a715f8358001f996801af67ea57e2f149ef32596da98fe509517b524e508d965` |

Both copied modules use only Python's standard library. No third-party source,
historical corpus, generated proof or external asset is imported here. The core
repository's project-level `LICENSE` is Apache-2.0; preserve third-party rights
and notices separately before any larger transfer. The project's `NOTICE` review
remains open.

## Boundary and stop conditions

- No semantic normalization, implicit content rewrites, source-to-target identity
  promotion, scanner evaluation, authoring compilation or proof rebaselining.
- No schema relocation or modification; 0.4 remains pinned under `schema/v0.4.0/`
  in `scap-ng` for the VS Code editor and existing toolchain builder.
- `tools/scap_ng_library/index.py`, `documents.py`, and `cli.py` still depend on
  `verify_v04_package_consumer`, `v04_direct_yaml`,
  `v04_a_authoring_graph_index`, compiler modules and the schema package. Do not
  move them solely because these two helpers now live here.
- `tools/build_versioned_toolchain.py` assumes one committed source tree. A
  separate exact-SHA two-repository packaging design and clean-extract proof
  is required before any release cutover.
- `scap-ng` code removal, workflow deletion, symlink rewrites and schema
  flattening require separate reviewed changes after dependency equivalence.

