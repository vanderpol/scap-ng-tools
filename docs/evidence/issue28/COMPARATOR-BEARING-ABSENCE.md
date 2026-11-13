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

The converter now emits `values_found: none` and records
`oval_absence_comparator_ignored` with the original attributes and source hash.
Nine primary Rules hit this recovery path; independent source vectors remain
required before promoting the warning to a proof claim.
