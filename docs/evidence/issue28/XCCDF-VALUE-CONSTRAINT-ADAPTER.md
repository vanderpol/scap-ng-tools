# XCCDF Value relational-constraint adapter

This is a valid, low-frequency conversion gap—not an unsupported capability.
The pinned corpus has **36 Rules** whose XCCDF `Value` is exported to an OVAL
external Variable while carrying a non-equality operator. `SV-226057` is a
representative source case.

The first native contract should preserve, without coercion:

1. the XCCDF datatype and selected/default value;
2. the check-export `value-id` → OVAL Variable identity;
3. finite `possible_value`/allowed-value constraints;
4. the relational operator (`less_than_or_equal` first);
5. cardinality and omitted/empty/invalid Input states.

The compiler must reject an invalid organization value and the runtime must
apply the same typed relation. An allowed-values list alone is insufficient:
it preserves the candidates but not the XCCDF operator. This remains an
explicit design decision until the native Input/Parameter constraint contract
is approved; the converter currently blocks these Rules rather than silently
changing their policy.
