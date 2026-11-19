# OVAL Self-Assertion Windows policy source correction — PR #5 focused qualification

This receipt verifies the source-invalid literal correction proposed in [Self-Assertion PR #5](https://github.com/OVAL-Community/SCAP-Self-Assertion/pull/5). It is not Windows host qualification or independent OVAL equivalence proof.

## Source evidence

The exact pinned base is `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`; PR #5 is `cc3be23f51913561c96aacaf36f4838a78100cdf`.

- `win-def_lockoutpolicy_test.xml`, Definition `oval:org.mitre.oval.test:def:705`, Test `tst:1268`, State `ste:1077`: `force_logoff` changes from `-1` to `0`.
- `win-def_passwordpolicy_test.xml`, Definition `oval:org.mitre.oval.test:def:998`, Tests `mil.niwc.winpassword.test:tst:10`–`:tst:70`: `max_passwd_age` changes from `-1` to `0`.

The source XML hashes and all IDs are recorded in the machine receipt. No `86400` threshold is introduced. That would narrow the broad support witness and could reject valid no-expiration configurations; `0` is the intended schema-valid lower bound for this content correction.

## Converter result

Using Tools `35f47240dab47931e3d77818b1a8f80b2cc26c91`, canonical `5ee55288b369da26f308f40813e545b78dff2753`, flat schema-family SHA-256 `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`, and OVAL schema commit `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`:

| Definition | Pinned base | PR #5 corrected |
|---|---|---|
| `oval:org.mitre.oval.test:def:705` | blocked: `policy source literal must be nonnegative` | `CONVERTED_UNVERIFIED`, schema validated |
| `oval:org.mitre.oval.test:def:998` | blocked: `policy source literal must be nonnegative` | `CONVERTED_UNVERIFIED`, schema validated |

Corrected native Assessment hashes are `13eef4c7...d6b64ce` and `6eb53450...1f76a2`; full values are in the JSON receipt. Runtime equivalence remains unproved.

## Reproduction

Fetch each file at both exact commits, run `direct04` with a fresh external output directory, and compare the statuses. Keep generated evidence outside Git. The machine-readable receipt contains the command template and all source identities.
