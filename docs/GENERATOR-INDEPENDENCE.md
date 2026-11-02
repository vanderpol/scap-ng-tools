# Portable 0.4 generator and CLI-oracle cutover audit

This checkpoint makes the **tools CI independent of the original**
`vanderpol/scap-ng` **research checkout**. It does not approve a repository
rename, merge, release, new baseline, VS Code editor work, proof, or scanner
execution.

## Pinned sources and exact byte parity

| Input | Exact identity | Role |
| --- | --- | --- |
| Frozen, flat 0.4 SCAP-NG schemas | `ed4a9dce01af6849bf4be146c7678ef7804051e4`, aggregate SHA-256 `476f5767276f5c2114f91b211cf4e159a75bee0806ea736fc631d9c40f4c4b80` | All 100 mapping records; 52 qualified for automatic conversion |
| Official OVAL 5.12.3 | [OVAL-Community/OVAL](https://github.com/OVAL-Community/OVAL/tree/2f140ee5c5dd1ed9606fcd5afc301f6baeb48706/oval-schemas), commit `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706` | Build-time original XSD field/type declarations |
| Historical SCAP-NG generator source | `vanderpol/scap-ng@d12a644f4607cdc9c9ada50e3a96d4fd0060c6d9` | Provenance of four byte-exact Apache-2.0 generator helpers, now in `scripts/_v04_generation` |
| Pinned NIWC Q3 2026 signed source ZIPs | `niwc-atlantic/scap-content-library@8c8e5dff860af6b1290ee9273a282db24278f8d5`, `Archive/2026_Q3/` | Four original immutable compatibility fixtures |

The four helper files' SHA-256 values are asserted by
`tests/test_converter_provenance.py`. The helper copies have **no
editor/runtime dependency** in the installed package. CI fetches public OVAL
schemas only to regenerate `contracts-0.4.0.json` and byte-compares the
result with the exact original 580,676-byte pack, SHA-256
`b78c4db59da4cb2bad4f783e9562a5df9060de1a0e60f29ff4afceef8443ca70`.

The original research XSD folder contains 54 OVAL files. Comparing exact Git
blobs against the official OVAL 5.12.3 commit yields **52 exact matches**.
The two differences are `independent-definitions-schema.xsd` and
`independent-system-characteristics-schema.xsd`, which carry extra historical
`sqlext` SQL test/item declarations. The 52-capability converter contract
pack is **identical** using official OVAL 5.12.3 without those additions. The
differences must be reconsidered separately when qualifying the entire 100-
capability authoring/editor metadata pack; they are not silently treated as
equivalent for that larger scope. Owner direction on 2026-11-02 explicitly
**defers `sqlext` migration**: its host-versus-SQL-database/instance targeting
semantics are not yet equivalent to `sql512`. Do not alias, convert, or claim
compatibility between them without a separately reviewed targeting contract.

The official OVAL terms permit use/modification/reproduction with its
license/disclaimer reproduced. This tools repository does **not redistribute**
the official XSD files in its wheel or Git repository; CI checks out the pinned
upstream commit. The accepted historical generator Python code is copied from
the SCAP-NG Apache-2.0 source, and its source identities are hash-audited.

## Independent original converter oracles

Before removing the source checkout from CI, the original
`v04_direct_converter.py` was run against the pinned Active Directory Domain
SCAP 1.4 ZIP in strict `--all-rules` mode. Its output contains **67 files**
excluding non-deterministic `metrics.json`. The SHA-256 of concatenating each
lexicographically sorted relative filename, a NUL byte, and its exact raw file
bytes is:

`7720a9efae45a7ba34ca107bcdeb0face751aae8126e2e14b5c16f07c6f8d6ff`

The tools CLI generates exactly the same 67 filenames and file bytes, excluding
its additional unverified-scope declaration. CI now checks that frozen original
CLI file-byte digest on every run even **without** a research checkout. The
complete 535-Rule inventory and strict conversion suite also checks the
original per-benchmark native JSON, coverage and source-trace digests, plus
negative semantic boundary mutations. No blocker count, native output or
proof status has been rebaselined.

When the original research source is available, setting
`SCAP_NG_RESEARCH_ROOT` continues to run its **live** CLI file-byte
differential and original semantic error differential as extra diagnostics.
These optional tests are not required for independent tools CI.

## Still out of scope

- Editor metadata export of **all 100** supported capabilities; its schema
  path, `sourceCommit` profile pin and 0.4 authoring annotations must be
  deliberately migrated and tested before VS Code tasking.
- `--draft`, `--compile`, `--verify`, scanner collection, independent source
  proof, and any new content admissions.
- Renaming `scap-ng-staging` to `scap-ng`, making the former research repo
  private, merging the stacked draft PRs, or publishing a new release.
