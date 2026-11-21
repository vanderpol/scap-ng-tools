# OVAL Self-Assertion macOS environment-variable witness — PR #6 focused qualification

This bounded receipt verifies a source typed-variable defect. It is not macOS host qualification or independent OVAL equivalence proof.

## Source evidence

- Repository: `OVAL-Community/SCAP-Self-Assertion`
- File: `SCAP_1.4/OVAL_Test_Content/macos/ind-def_environmentvariable58_test_mac.xml`
- Definition: `oval:navy.navwar.niwcatlantic.scc.test:def:1`
- Variable: `oval:navy.navwar.niwcatlantic.scc.test:var:2`
- Tests: `tst:1`, `tst:2`, `tst:3`
- Base commit/hash: `e3538595c5083b9c34d937a81d319234df9bbfaa` / `aebed7527b5717f94755c28e37ee3357debaca7d3c024814f0b3c501e387ad16`
- PR #6 corrected commit/hash: `33c6ad2bb254f2c60274a19891a9f9973f985e76` / `8a7d8c49cb312607f8d88cd2a1ec42f8ad8871bf31413a5e5c667cf5208e2319`

The base Variable declared `boolean` while it is used as a process PID and the referenced process `pid` field is `int`. PR #6 changes only that declaration/comment and versions; source IDs and Test graph remain intact. Both hashes were recomputed from exact Git blobs.

## Focused conversion

Using Tools `35f47240dab47931e3d77818b1a8f80b2cc26c91`, canonical `5ee55288b369da26f308f40813e545b78dff2753`, flat schema-family SHA-256 `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`, and OVAL schema commit `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`:

| Input | Status | Schema validated | Assessment SHA-256 |
|---|---|---:|---|
| Pinned base | blocked: `Variable cast outside bounded proof` | no artifact | — |
| PR #6 corrected | `CONVERTED_UNVERIFIED` | yes | `f10abbe558387a3fed09a7a5d03fee7e8d71d8409961d4948768db65cfc057ac` |

Runtime and independent equivalence remain unproved.

## Reproduction

Fetch both exact source commits and run `direct04` for Definition `oval:navy.navwar.niwcatlantic.scc.test:def:1` into fresh external directories. Generated artifacts remain outside Git; the machine receipt records exact hashes and the command template.
