# OVAL 5.12.3 deprecation source receipt

This is a source-schema audit, not a converter or scanner qualification. It
classifies only official `oval:deprecated_info` annotations from the pinned
OVAL-Community/OVAL checkout.

- Source commit: `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706` (5.12.3)
- Schema directory: `oval-schemas`
- Definition schema files inspected: **23**
- Top-level declarations inventoried: **1,033**
- Directly deprecated declarations: **215**
- Declarations containing nested deprecated members: **55**
- Official deprecation annotations: **307**
- Schema manifest SHA-256: `5b71250dd5fe97dca2776e94fba2b0a3f5decea3707c672fc402836324e24721`

The complete source-file hashes and affected declaration/member records are in
[`oval-schema-deprecation-summary.json`](oval-schema-deprecation-summary.json).

## Important distinctions

- A declaration is marked `deprecated` only when it carries its own
  `oval:deprecated_info`. A valid declaration with one deprecated field,
  attribute, or enumeration remains **unclassified**, with the nested marker
  retained. This avoids treating `rpmverifyfile_state` as deprecated merely
  because `md5_differs` is.
- Exact source evidence includes `linux:rpmverifyfile_state/md5_differs`,
  deprecated in `5.11.1:1.1` and replaced by `filedigest_differs`; and
  `linux:RpmVerifyFileBehaviors/@nomd5`, deprecated in `5.11.1:1.1` and
  replaced by `nofiledigest`.
- `independent:FileBehaviors` contains the enumeration value
  `recurse_direction=up`, marked for removal in `5.12.3` because it is unused
  and adds complexity. This is a source-language deprecation; it is not a
  reason to add upward recursion to SCAP-NG.

No record in this receipt authorizes native conversion or runtime support.
Deprecated constructs remain explicit holds; nondeprecated constructs still
require canonical representability, converter parity, and RI qualification.
