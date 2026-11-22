
## Minimal canonical requirement: dynamic literal functions

The active schema has no expression variant for dynamic `escape_regex` or
`glob_to_regex`. The smallest canonical amendment should add two typed
expression variants under `variable-expression.schema.json#/$defs/expression`:

```yaml
escape_regex:
  value: <expression>
glob_to_regex:
  glob_noescape: <boolean, default false>
  value: <expression>
```

Source evidence is `EscapeRegexFunctionType` at XSD lines 823–842 and
`GlobToRegexFunctionType` at lines 961–1088 in the pinned OVAL 5.12.3 schema.
Each operation must run independently for every produced value, preserve order
and multiplicity, and propagate missing/error/unknown/incomplete/not-collected/
not-applicable statuses. `glob_to_regex` must preserve the `glob_noescape`
default and bound output population/bytes. Malformed glob input is an error;
record operands must not be flattened.

Positive source witnesses:

- `escape_regex` containing an `object_component` value projection.
- `glob_to_regex glob_noescape="false"` containing a string `variable_component`.

Negative witnesses:

- Missing required component.
- Invalid `glob_noescape="maybe"`.
- Native record-valued operand.

Converter action remains **held** until canonical approval and repinning;
static literal-only lowering remains bounded and source-traced. RI acceptance
must cover bounded collection/bytes, empty and malformed inputs, all diagnostic
statuses, trusted regex behavior, timing, truncation and provenance.
