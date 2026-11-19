# OVAL Self-Assertion UNIX SSHD witness — PR #17 focused qualification

This bounded receipt verifies a source-content defect: a valid Test criterion was hidden inside an XML comment. It is not UNIX host qualification or independent OVAL equivalence proof.

## Source evidence

- Repository: `OVAL-Community/SCAP-Self-Assertion`
- File: `SCAP_1.4/OVAL_Test_Content/unix/unix-def_sshd_test.xml`
- Definition: `oval:org.mitre.oval.test:def:963`
- Base commit/hash: `e3538595c5083b9c34d937a81d319234df9bbfaa` / `a39e832aec71f537ff18eeaac3b181c7f63d6dbe5c311a8d7221ce86258ec8f0`
- PR #17 corrected commit/hash: `d3c93ced3a7518e875d61079d945ade6669af442` / `ae085feed857e10466bb97623a15da533f09a909a4151b33c69e7e66f584759b`
- Affected Test: `oval:org.mitre.oval.test:tst:483`

The source already contained a valid `sshd_test` with two State references for `ClientAliveInterval >= 1` and `<= 300`. The Definition criterion was commented out. PR #17 activates that criterion and increments the Definition version without changing the Test/Object/State graph.

## Focused conversion

Using Tools `35f47240dab47931e3d77818b1a8f80b2cc26c91`, canonical `5ee55288b369da26f308f40813e545b78dff2753`, flat schema-family SHA-256 `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`, and OVAL schema commit `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`:

| Input | Status | Schema validated | Native Test count | Assessment SHA-256 |
|---|---|---:|---:|---|
| Pinned base | `CONVERTED_UNVERIFIED` | yes | 3 | `420d762102b56e11109292718e9d090f347d94e3527a0e3a91ce5a2d3c168396` |
| PR #17 corrected | `CONVERTED_UNVERIFIED` | yes | 4 | `6efe348de3a69f66fbe0b124badd7aab16592a715aec68fab135b54a5f6334ae` |

The corrected native Assessment includes the ClientAliveInterval Test titled “SSHD parameter ClientAliveInterval is between 1 and 300.” Runtime and independent equivalence remain unproved.

## Reproduction

Fetch both exact source commits and run `direct04` with Definition `oval:org.mitre.oval.test:def:963` into fresh external directories. Compare the native Test counts and retain source-trace differences as provenance evidence. Generated artifacts remain outside Git; the machine receipt records the command template and hashes.
