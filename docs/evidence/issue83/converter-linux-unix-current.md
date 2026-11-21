# Current Linux/Unix OVAL witness conversion

Exact pinned source-witness conversion through the production converter:

- Source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`
- Converter: `13af669`
- Canonical schema: `5ee55288b369da26f308f40813e545b78dff2753`
- Schema family: `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`
- Witness receipt: `d4741fdae77705015bdbe060f5be8b35ea88cc01b7cf0062660fd7ddec32018e`

## Linux

- 62/62 converted; 0 blocked
- Receipt: `/tmp/tools-issue83-current-conversion-linux-final-1795107920/receipt.json`
- SHA-256: `3f00955109b4f9c43f762de2a6f5b0726046bf6ff86ae93733f015693a745f5e`

## Unix

- 71/72 converted; 1 blocked
- Blocked source: `unix/ind-def_textfilecontent54_test_unix.xml`
- Test: `oval:org.mitre.oval.test:tst:466`
- Test structural SHA-256: `e5603b25af6d9c2c6c295e4696657e098b869d545b310d28097ff4a2aa5d8c4a`
- Authored `recurse_direction="up"`, `max_depth="1"`
- Receipt: `/tmp/tools-issue83-current-conversion-unix-final-1795108047/receipt.json`
- SHA-256: `3985958bec61ffae577bb7ae4b37f71989e52fc8480448e5302ba5db68043294`

The Unix blocker is the deprecated OVAL upward-recursion source construct.
SCAP-NG upward recursion was not introduced. Conversion results are not
runtime or independent-equivalence proof.
