# Copy-first migration record — 2026-11-02

Status: **historical initial import record**. The canonical repo cutover
completed on 2026-11-02, with no research source deletion or release.

The owner authorized a safe, staged cleanup after the 0.4 schema-family freeze.
The source repository, now private `vanderpol/scap-ng-research`, retained its
original files and historical versioned schemas. Its freeze merge is `1401c2851516e1af230231abe47a40419bca3dc1`,
followed by the Apache-2.0 license commit `d12a644f4607cdc9c9ada50e3a96d4fd0060c6d9`.

| Source path in `scap-ng-research` | Destination | SHA-256 of file bytes |
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
- At this initial checkpoint there was no schema relocation or modification.
  Historical 0.4 remains under `schema/v0.4.0/` in `scap-ng-research`;
  current public `scap-ng` has the byte-identical frozen 0.4 tree in flat
  `schema/`.
- `tools/scap_ng_library/index.py`, `documents.py`, and `cli.py` still depend on
  `verify_v04_package_consumer`, `v04_direct_yaml`,
  `v04_a_authoring_graph_index`, compiler modules and the schema package. Do not
  move them solely because these two helpers now live here.
- `tools/build_versioned_toolchain.py` assumes one committed source tree. A
  separate exact-SHA two-repository packaging design and clean-extract proof
  is required before any release cutover.
- Research code removal, workflow deletion and symlink rewrites still require
  separate reviewed changes. Canonical schema flattening has been qualified.


## Approved native discovery follow-up — Issue #12

The original imports and hash receipts above are preserved as history. The
[approved discovery follow-up](NATIVE-INPUT-DISCOVERY-RECEIPT.json) allowlists
only the converter's derived discovery emission and the presence traversal
correction for real record members named like metadata. The new pure authoring
index is written against the approved public contract. Generator helper bytes,
semantic contract JSON, unrelated runtime sources and original-source goldens
remain pinned. This is a bounded adaptation, not an assertion that all runtime
files remain byte-for-byte original copies.
