# Issue #59: native split/substring collected-value projection

This isolated candidate builds on Tools PR #62 at base commit `eb03a8aaaa000a9486f2575e841cb79d5a01e49b`. It fixes a converter-path inconsistency without changing the canonical SCAP-NG 0.4.1 schema, the source OVAL XML, or the provenance-pinned original OVAL visitor.

## Defect and bounded correction

The existing native lowering adapter inserted an explicit `concat: [{literal: ""}, <collected-field-values>]` lexical projection when a legacy `function: {name: split|substring}` envelope contained a direct collected-field `values` expression. An already-native `split` or `substring` expression referencing exactly the same `values` node did **not** receive this projection. Therefore, equivalent source adapter paths could have different acceptance behavior. Both paths now share one explicit source-text projection helper and lowering is idempotent.

The empty-prefix `concat` is visible in authored YAML/JSON. It is **not** a hidden converter datatype assumption, not an inferred string value from numeric-looking text, not a Variable declaration datatype, and not a datatype assertion on the collected Item. The runtime must preserve original source order, multiplicity, Cartesian mapping, and missing/error/incomplete statuses, rejecting non-scalar evidence. No scalar literals, other Variable references, or previously-lowered expressions are rewritten.

## Regression tests and safety boundaries

`tests/test_issue59_native_text_projection.py` checks exact native/source-envelope parity, no original AST mutation, idempotence, no unapproved numeric-literal cast, preservation of a directly referenced Item field, and absence of fabricated collected values. CI must run this alongside the existing source function tests, the exact 0.4.1 semantic-pack handshake, the full 59-active Rule-ID rebuild, and source-truth vectors.

This is **not** a recovery receipt: no additional Rules are considered admitted until an original signed-source full-65 rebuild produces exact Rule-ID transitions, all relevant CI checks pass, and downstream native/OVAL/RI status/equality semantics are proved. The 114 ambiguous collected-field, 17 `unique`, and other unresolved datatype cases remain on release HOLD rather than being guessed away.
