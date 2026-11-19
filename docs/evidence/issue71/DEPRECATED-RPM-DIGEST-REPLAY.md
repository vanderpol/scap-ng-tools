# Signed source replay: deprecated RPM digest fields

This gate tests original NIWC Atlantic Q3 2026 signed OL7 V16 and RHEL7 V19
Rules `SV-221653` and `SV-214799`. Both use OVAL
`rpmverifyfile_state/md5_differs` and the corresponding Object behavior
`nomd5`, both deprecated as of Linux extension `5.11.1:1.1`,
with approved replacement spellings `filedigest_differs` and `nofiledigest`.

The current canonical `linux.rpmverifyfile` mapping has these exact aliases.
This test must confirm the original signed Rule converts to native 0.4.1 with
an immutable archive commit, print the archive SHA-256, and retain the original
source deprecation provenance. Conversion alone does **not** prove scanner or
OVAL runtime truth parity. Do not erase these Rules from the historical ledger;
keep both normative status and current conversion disposition.

Schema: `OVALProject/Language/schemas/linux-definitions-schema.xsd`,
`oval:deprecated_info` for both names, `oval:version 5.11.1:1.1`.
