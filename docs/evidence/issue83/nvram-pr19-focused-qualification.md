# OVAL Self-Assertion macOS NVRAM witness — PR #19 focused qualification

This bounded receipt verifies a source documentation/content correction. It is not macOS runtime qualification or independent OVAL equivalence proof.

## Defect and correction

Pinned source file:

- Repository: `OVAL-Community/SCAP-Self-Assertion`
- Path: `SCAP_1.4/OVAL_Test_Content/macos/macos-def_nvram512_test.xml`
- Definition: `oval:org.mitre.oval.test:def:448`
- Base is PR #8's head `9d3ae629da96bf8b15730a5c6ac274cf29fcd7d5`; SHA-256 `15ab1e122b7b58d40c1b81dc71a512a9e55b01c4ce0aeaed35e85160aec0a2ef`.
- Correction is PR #19's head `0a1ee9365aff7962118f316ed9df822217bbf850`; SHA-256 `78276118a5c5e503b2ae9b82395d39a3b673711a79fe5e89945921ca2d148058`.

PR #19 corrects comments and increments versions for:

- Object `oval:org.mitre.oval.test:obj:754`: `AppleSecureBootPolic` → `AppleSecureBootPolicy`.
- State `oval:org.mitre.oval.test:ste:994`: incorrect `SystemAudioVolume`/regex description → `AppleSecureBootPolicy`/binary `not equal 00`.
- States `oval:org.mitre.oval.test:ste:569` and `:ste:943`: incorrect regex descriptions → binary `not equal 00`.

The authored IDs, operations, datatypes, values and references are unchanged. Affected Tests are `oval:org.mitre.oval.test:tst:865`, `:tst:486` and `:tst:308`.

The base and corrected XML hashes were independently verified from their exact Git blobs. PR #19 is intentionally dependent on PR #8; merge PR #8 first.

## Focused conversion

Using Tools `35f47240dab47931e3d77818b1a8f80b2cc26c91`, canonical `5ee55288b369da26f308f40813e545b78dff2753`, flat schema-family SHA-256 `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`, assessment-execution schema-family SHA-256 `326f82668020a717f5d3443484330f313146978292befd75c063f55b2e4e5329`, and OVAL schema commit `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`, `direct04` converted both exact source blobs:

| Input | Status | Schema validated | `assessment.json` SHA-256 |
|---|---|---:|---|
| PR #8 base | `CONVERTED_UNVERIFIED` | yes | `6d08ccf4da04224ef353c4c07832df4b28607cc1f5eed65813cd965a3bbccaae` |
| PR #19 corrected | `CONVERTED_UNVERIFIED` | yes | `6d08ccf4da04224ef353c4c07832df4b28607cc1f5eed65813cd965a3bbccaae` |

The native Assessment bytes are identical, as expected for a correction limited to comments and source entity versions. Source-trace and conversion-scope hashes differ because they preserve source provenance; this is not a semantic native change.

## Reproduction

Keep generated output outside Git and use fresh directories. Fetch the base blob at `9d3ae629da96bf8b15730a5c6ac274cf29fcd7d5` and corrected blob at `0a1ee9365aff7962118f316ed9df822217bbf850`. Run `direct04` for Definition `oval:org.mitre.oval.test:def:448` twice with the command template in [`nvram-pr19-focused-qualification.json`](nvram-pr19-focused-qualification.json), substituting each exact source SHA-256 and commit. Compare only `assessment.json` for native semantic projection; retain source-trace differences as provenance evidence.

Machine receipt: [`nvram-pr19-focused-qualification.json`](nvram-pr19-focused-qualification.json).
