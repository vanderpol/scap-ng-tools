# Multi-component aggregation recovery

This is a tracked converter/compiler recovery item affecting **30 Rules**.
The source shape is an OVAL `unique` or `merge` function with multiple child
components, for example Firefox Linux `SV-251546`.

The recovery visitor now preserves the source component list and emits the
canonical function-call candidate for multi-component `unique` and `merge` in
`native_recovery` mode. `count` likewise preserves one-or-more components;
counting only the first operand was an incorrect lowering. The default path
still fails closed with `multiple aggregation components need an approved
collection expression`.

The active 0.4 Variable-expression schema currently admits only one collection
operand for `unique`/`merge` and does not admit canonical calls in Assessment
Variables. Therefore these exact candidates remain schema/compiler-gated and
are not included as converted or proved Rules. The candidate preserves source
order, duplicates before `unique`, empty collections, datatype/error status
boundaries, and nested expressions; it never substitutes concatenation or Set
union. Source IDs and the original function XML remain in the conversion
binding/provenance.
