# Multi-component aggregation recovery

This is a tracked converter/compiler recovery item affecting **30 Rules**.
The source shape is an OVAL `unique` or `merge` function with multiple child
components, for example Firefox Linux `SV-251546`.

The implementation must preserve the ordered collection boundary, duplicates,
empty collections, datatype errors, and nested functions. It must not silently
choose concatenation or a set union, since those operations are not generally
equivalent to OVAL aggregation. The current converter fails closed with
`multiple aggregation components need an approved collection expression` until
the native collection-expression contract is approved and independently
proved.
