# OVAL `concat` crosswalk

This is a feature-level source-to-native receipt, not a claim of scanner or
independent OVAL equivalence.

## Normative source

Pinned OVAL 5.12.3 `oval-definitions-schema.xsd` defines
`oval-def:ConcatFunctionType` (lines 770–802). The inherited `ComponentGroup`
and `FunctionGroup` (lines 636–646 and 708–728) permit object, Variable,
literal, and nested function components. The normative documentation requires
ordered concatenation, lexical casting when a component is not already text,
Cartesian expansion for collection-valued components, and preservation of a
missing/non-success component status.

## Native mapping

The active 0.4.1 mapping is
`variable-expression.schema.json#/$defs/expression/oneOf/4`:

```yaml
concat:
  - <expression>
  - <expression>
```

`lower_expression` preserves the ordered component graph. The shared semantic
gate now admits collected Item fields whose source capability exposes multiple
scalar datatypes without selecting one datatype. It uses the same explicit
textual boundary for `concat`, `split`, `substring`, `begin`, `end`, and
`regex_capture`. Records, unknown/empty type domains, and malformed expressions
remain fail-closed.

## Evidence

- Source schema SHA-256: `06b79e8683d6b9dcaad3ab074a456588ed82c4edd2e8fff209def10aa0a366cc`
- Canonical schema: `c428fd0708da0cdd574dc9e499db714a1068bd75`
- Production converter: `src/scap_ng_tools/converter/native041_function_lowering.py`
- Shared semantic gate: `src/scap_ng_tools/converter/_v04_semantic/v04_variable_expressions.py`
- Focused vectors: `tests/test_issue83_concat_crosswalk.py`
- Independent source Cartesian vectors: `tools/issue28_semantics.py`

The focused vectors cover mixed typed collected populations, all shared textual
consumers, record rejection, and untyped-empty rejection. They do not execute
a scanner, acquire host Items, or prove independent OVAL equivalence.
