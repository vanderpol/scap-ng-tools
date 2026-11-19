# OVAL Self-Assertion merge witness — PR #7 focused qualification

This is a bounded source-correction check, not a full-corpus replay or runtime equivalence claim.

## Source defect and correction

Pinned base source:

- `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`
- `SCAP_1.4/OVAL_Test_Content/agnostic/oval-def_merge.xml`
- SHA-256: `e9cf10371c2d41a3c92087a93f62f597043828d0914a21c5ab4314f03fd8a6ef`

Upstream correction: [PR #7](https://github.com/OVAL-Community/SCAP-Self-Assertion/pull/7), head `c06d4899af19147a12add8008859a29a1de579e4`.

The source declared string-valued `var:3`, `var:4`, and `var:101` as `datatype="int"`. PR #7 changes them to `datatype="string"` and increments the affected Definition/Variable versions. Corrected source SHA-256:
`1f70fe9df3ec30eb5f2d61a27307514ab85764187f287354b3b90d19e4d6b3ee`.

This is classified as a **source content defect**, not a canonical-language change or converter workaround.

## Focused conversion

Using Tools `a150d36b0d259a74cdbcd1887a0943687e222e27`, canonical `5ee55288b369da26f308f40813e545b78dff2753`, schema-family SHA-256 `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`, and OVAL schema `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`:

| Input | Converter status | Schema validated | Assessment SHA-256 |
|---|---|---:|---|
| Base source | `CONVERTED_UNVERIFIED` | yes | `4cbbc6644c1de30afac52eb7e928bf9a56dbfc907f65cc12d9133d568235d3f2` |
| PR #7 source | `CONVERTED_UNVERIFIED` | yes | `9a863c12efd97ae2ff46cdf5e4ef05d77ff182288aa7a2099f2036bf9c748788` |

After removing only generated Assessment `version`, the semantic projection SHA-256 is identical for both runs:
`38f037d6de8ab55d702c3f96a9cfee674f4cf97988c24df45f8d4e143bca8623`.

This proves the correction preserves the converted semantic projection in this focused case. It does **not** prove source/runtime equivalence. The invalid base source must not be retained merely because the current converter can produce an artifact from it.

## Reproduction

Fetch the exact PR head and run `direct04` twice with the command recorded in the machine-readable receipt. Use a fresh output directory each time; the converter refuses overwrite. Full generated outputs remain external under `/tmp/issue83-merge-pr7-1795118024`; only hashes are committed.

Machine receipt: [`merge-pr7-focused-qualification.json`](merge-pr7-focused-qualification.json).
