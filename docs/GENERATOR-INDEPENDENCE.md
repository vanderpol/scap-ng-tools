# Portable 0.4 generator and CLI-oracle cutover audit

This checkpoint makes the **tools CI independent of the preserved private**
`vanderpol/scap-ng-research` **checkout**. The owner completed the separate
repository renames and approved tools merges on 2026-11-02; that did not approve
a release, new baseline, scanner execution, or independent proof.

## Pinned sources and exact byte parity

| Input | Exact identity | Role |
| --- | --- | --- |
| Owner-amended, flat 0.4 SCAP-NG schemas | `354c9c962c77488a3d939cab56f6ceecfd495d27` (draft PR #4), aggregate SHA-256 `ab1933f2d9171ee0af70c0fab855b00f5faf78bf59ad4924fbf24b402ac4072a` | All 100 mapping records; 52 qualified for automatic conversion |
| Official OVAL 5.12.3 | [OVAL-Community/OVAL](https://github.com/OVAL-Community/OVAL/tree/2f140ee5c5dd1ed9606fcd5afc301f6baeb48706/oval-schemas), commit `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706` | Build-time original XSD field/type declarations |
| Historical SCAP-NG generator source | `vanderpol/scap-ng-research@d12a644f4607cdc9c9ada50e3a96d4fd0060c6d9` (private) | Provenance of four byte-exact Apache-2.0 generator helpers, now in `scripts/_v04_generation` |
| Pinned NIWC Q3 2026 signed source ZIPs | `niwc-atlantic/scap-content-library@8c8e5dff860af6b1290ee9273a282db24278f8d5`, `Archive/2026_Q3/` | Four original immutable compatibility fixtures |

The four helper files' SHA-256 values are asserted by
`tests/test_converter_provenance.py`. The helper copies have **no
editor/runtime dependency** in the installed package. CI fetches public OVAL
schemas only to regenerate `contracts-0.4.0.json` and byte-compares the
result with the exact 580,676-byte **owner-amended** pack, SHA-256
`e489a14931b627e67c20724b82fc6b959e3bbf396da07e86cd51d47a08ee915a`.
The original pre-release pack had digest
`b78c4db59da4cb2bad4f783e9562a5df9060de1a0e60f29ff4afceef8443ca70`;
all capability and behavior contents remain unchanged.

The original research XSD folder contains 54 OVAL files. Comparing exact Git
blobs against the official OVAL 5.12.3 commit yields **52 exact matches**.
The two differences are `independent-definitions-schema.xsd` and
`independent-system-characteristics-schema.xsd`, which carry extra historical
`sqlext` SQL test/item declarations. The 52-capability converter contract
capability and behavior sections are **identical** using official OVAL 5.12.3 without those additions. The
separate [100-capability editor-pack audit](EDITOR-PACK-CUTOVER.md) also
reproduces all 235 deliberately reviewed derived resources
without those additions; it does not qualify missing SQL targeting behavior.
Owner direction on 2026-11-02 explicitly
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

The owner-approved pre-release 0.4 `item_requirement` change deliberately
updates those 67 authoring file bytes to digest
`d5a38ab93c9ffb9852a529b4de8860bbd848973963b5a2935958b6c61b1c073f`.
The original digest above remains a historical reference; the new CI golden
is a separately recorded serialization baseline. All 535 source Rules,
380 admissions, 155 blocks, and source trace/coverage hashes remain unchanged.
No semantic proof status has been rebaselined.

When the original research source is available, setting
`SCAP_NG_RESEARCH_ROOT` runs an optional *normalized structured-document*
comparison (old ungrouped Item counts upgraded before comparison) and
original semantic error diagnostics, not byte parity between grammars.
These optional tests are not required for independent tools CI.

## Still out of scope

- Owner-controlled publication and **editor consumption** of the separately
  audited 100-capability pack; the existing VS Code `sourceCommit` profile
  must be repointed in a reviewed PR after canonical repository rename.
- `--draft`, `--compile`, `--verify`, scanner collection, independent source
  proof, and any new content admissions.
- Public release packaging, publication of editor metadata, and external
  VS Code PR tasking are separate from the now-completed repository renames
  and tools PR merges.
