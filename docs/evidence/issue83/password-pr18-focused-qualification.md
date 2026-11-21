# OVAL Self-Assertion UNIX password witness — PR #18 focused qualification

This bounded check verifies a source-content correction; it is not runtime qualification or independent OVAL equivalence proof.

## Defect and correction

Pinned base source:

- `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`
- `SCAP_1.4/OVAL_Test_Content/unix/unix-def_password_test.xml`
- SHA-256: `b09a04f5b562cee3d84ac41b2b99dbd6326f48aa50b8a037dcd7163449827472`

Upstream correction: [PR #18](https://github.com/OVAL-Community/SCAP-Self-Assertion/pull/18), head `8728b036c093f90ddb05b7b5d330ed4f206b4c18`.

Test `oval:navy.navwar.niwcatlantic.scc.test:tst:362` is titled and referenced as the variable-backed pattern case, but it used literal-pattern Object `obj:625`. PR #18 changes only that Test's Object reference to variable-backed `obj:24` (`var:549`, `var_check="all"`) and increments Test version 1 → 2. Object `obj:625` remains the literal-pattern witness for `tst:673`.

Corrected source SHA-256: `7ea3fa94f473cf1000f6a9f89f8314e96fe74b93ad3536fd314276a6d1fd6a37`.

The recorded XML hashes were independently matched against `git show` at both exact source commits.

## Focused conversion

Using Tools `8bb2eae4f93422f6d93d35a9a8d516739d8490c`, canonical `5ee55288b369da26f308f40813e545b78dff2753`, full schema-family SHA-256 `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`, and assessment-execution closure SHA-256 `326f82668020a717f5d3443484330f313146978292befd75c063f55b2e4e5329`:

| Input | Converter status | Schema validated | Assessment SHA-256 |
|---|---|---:|---|
| Base source | `CONVERTED_UNVERIFIED` | yes | `f6fec0312da86fcdac89ce34ecc79ee49160cd722cbb08b117c7c04d7b362e18` |
| PR #18 source | `CONVERTED_UNVERIFIED` | yes | `f7733c958b6465213de5ab5cbf4fb9d95d136e43a096c9f045ff63e8c698b8a5` |

The corrected native Test explicitly contains `username.matches_regex: ["^[^r]"]`, `value_match: every`, and `datatype: string`. The base native Test retained the literal Object reference, so the source correction changes semantics as intended.

## Reproduction

Fetch the exact PR head and run `direct04` twice with the command in the machine-readable receipt. Use fresh output directories; generated outputs remain external under `/tmp/issue83-password-pr-obj24-1795118400`.

Machine receipt: [`password-pr18-focused-qualification.json`](password-pr18-focused-qualification.json).
