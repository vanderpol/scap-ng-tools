# OVAL Self-Assertion agnostic external-float witness — PR #14 focused qualification

This receipt verifies a source-comment fidelity correction. It deliberately does **not** claim that PR #14 resolves the separate canonical external-Variable/Input contract hold.

## Source evidence

- Archive: `SCAP_1.4/OVAL_Test_Content/agnostic/oval-def-ext.zip`
- Member: `oval-def-ext.xml`
- Definition: `oval:org.mitre.oval.test:def:562`
- Test: `oval:org.mitre.oval.test:tst:936`
- Base source: `e3538595c5083b9c34d937a81d319234df9bbfaa`, archive SHA-256 `d062d308545db20d090ccb516d8e6d804fa584704e8e5c5987f18ca5ef53fa10`, member SHA-256 `48b14ebc959d86f8911b5ca4b614ce0e0bff24f1183184cf6632f42f4945beb5`.
- PR #14 source: `50f801e3f4bdb5d3f6583195ad2ce29a2920546d`, archive SHA-256 `6ff45b5a85b77eadce11397d30adbdd011eb1d32fa3566d23b60322597ac5bdf`, member SHA-256 `df3a7bfbcf54b48652ed5c5ece93131c4c82ac2f07ff4056f5ed4668160dc8c1`.

PR #14 corrects comments from integer to float and increments the Definition/Test versions. It preserves `datatype="float"`, value `1.23456`, external-variable references and restrictions. The source hashes were independently recomputed from exact Git blobs.

## Conversion result

Using Tools `35f47240dab47931e3d77818b1a8f80b2cc26c91`, canonical `5ee55288b369da26f308f40813e545b78dff2753`, flat schema-family SHA-256 `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`, and OVAL schema commit `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`, both exact source versions remain blocked with:

`unbound external Variable or unsupported possible_restriction`

This is the correct result: the content correction improves authoring fidelity but cannot invent an Input binding or alter canonical semantics. Runtime and independent equivalence remain unproved.

Machine receipt: [`agnostic-external-float-pr14-focused-qualification.json`](agnostic-external-float-pr14-focused-qualification.json).
