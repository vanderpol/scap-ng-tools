# OVAL Self-Assertion UNIX upward-recursion witness — PR #16 focused qualification

This receipt documents removal of a deprecated source construct. It does not add upward recursion to SCAP-NG and is not UNIX runtime or independent OVAL equivalence proof.

## Source evidence

- File: `SCAP_1.4/OVAL_Test_Content/unix/ind-def_textfilecontent54_test_unix.xml`
- Definition: `oval:org.mitre.oval.test:def:48`
- Removed Test/Object/State: `tst:466` / `obj:577` / `ste:697`
- Base commit/hash: `e3538595c5083b9c34d937a81d319234df9bbfaa` / `876dbcd2a5bebfd5e0479f7bd0715736e53ab8b3553ced06832f95a61138b086`
- PR #16 corrected commit/hash: `799e8d6dbc43fe68044996c9cf2628f13c17a320` / `41e5e9db72584a0cd1925744822168d4f524ce177b69114be6e8f2b61ce9c626`

The baseline contains `recurse_direction="up"`, which OVAL 5.12.3 deprecates. PR #16 removes only that witness and its criterion. The same file retains valid downward-recursion witnesses (`tst:258` and `tst:96`). Exact hashes were recomputed from Git blobs.

## Focused conversion

Using Tools `35f47240dab47931e3d77818b1a8f80b2cc26c91`, canonical `5ee55288b369da26f308f40813e545b78dff2753`, flat schema-family SHA-256 `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`, and OVAL schema commit `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`:

| Input | Status | Schema validated | Assessment SHA-256 |
|---|---|---:|---|
| Pinned base | blocked: `unsupported/deprecated recursion direction` | no artifact | — |
| PR #16 corrected | `CONVERTED_UNVERIFIED` | yes | `3cc302f3a9b0c16fa4f2cc16fe1b86db9ed6fc37d1b487df9b0aec3d106043f2` |

No upward-recursion behavior is enabled. Runtime and independent equivalence remain unproved.

Machine receipt: [`unix-upward-recursion-pr16-focused-qualification.json`](unix-upward-recursion-pr16-focused-qualification.json).
