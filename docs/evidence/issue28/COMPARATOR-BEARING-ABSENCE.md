# Comparator-bearing absence

This category is different from the converter-only cases. The native 0.4
schema currently defines absence as comparator-free (`values_found: none`) and
explicitly does not provide a representation for an absence predicate carrying
an OVAL comparator.

Representative SLES 12 source:

```xml
<independent:stderr_line
    check_existence="none_exist"
    operation="pattern match">.*</independent:stderr_line>
```

The converter rejects this rather than emitting `values_found: none` and
silently discarding `operation="pattern match"`. The design decision is whether
OVAL processors treat the comparator as irrelevant once `none_exist` is applied,
or whether SCAP-NG needs an explicit absence-with-predicate form. A source
semantic proof is required before lowering it. Nine primary Rules currently hit
this boundary.
