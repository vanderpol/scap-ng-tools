# Ordered float comparison recovery

The converter now supports the ten corpus Rules using OVAL `datatype="float"`
ordered comparisons in opt-in `native_recovery` mode. This follows the
owner-coordinated SCAP-NG 0.4 contract
`scap-ng-0.4.0-binary32-comparisons/1` (contract SHA-256
`676dfd1bbe1e83e781e68c9c66fd4e53ed6f9da4278affbd0a877edf49ab03dd`).

Expected source decimals are parsed as exact decimal rationals and rounded
directly to IEEE-754 binary32, round-to-nearest-even. The converter then emits
the existing typed `float_*` predicate with a JSON-safe finite number. It does
not convert through host binary64, coerce to integer, or write nonfinite JSON
numbers. Signed zero, subnormal rounding, midpoint ties, malformed lexical
forms, and finite values overflowing binary32 are handled explicitly. `INF`,
`-INF`, and `NaN` expected values remain blocked by the approved finite-expected
contract.

Each recovered predicate retains its original lexical text, source entity hash,
contract identity/hash, and a warning that scanner/runtime evaluation was not
performed. The default converter path still rejects float recovery, preserving
historical output. Schema validation confirms the existing float comparison
vocabulary; this recovery does not claim compiler, scanner, or source-result
equivalence.

Representative source: Ubuntu 18.04 `SV-219237`:

```xml
<independent:subexpression datatype="float"
    operation="greater than or equal">10.0</independent:subexpression>
```

Exact regression vectors include `9.9999999 → 10.0`, ties-to-even on both
sides of a binary32 midpoint, minimum subnormal, signed-zero underflow, maximum
finite value, overflow rejection, and malformed/nonfinite rejection.
