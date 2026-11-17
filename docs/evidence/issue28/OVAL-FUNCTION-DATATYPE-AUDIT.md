# OVAL function-result datatype audit

This audit covers the eight remaining function-target Rules from the candidate
ledger. No source declaration was changed, no implicit cast was added, and no
Rule was promoted.

## Decision evidence

The pinned OVAL 5.12.3 XSD says that a Variable's returned values must comply
with its declared `datatype`, otherwise an error should be reported. The
FunctionGroup documentation describes attempted casts for components supplied
to functions, but does not define a general cast from a completed function
result into an enclosing `local_variable/@datatype`.

The function documentation gives these result domains:

- `arithmetic`: integer or float.
- `split`: a collection of strings.
- `count`: an integer count.

The source Rules declare incompatible result datatypes. The pinned Schematron
checks arithmetic and split *components*, but does not reject these enclosing
Variable declarations. Therefore XML/Schematron validity alone is insufficient.

An OpenSCAP 1.3.9 probe was also run with validation skipped. It observed numeric
results represented as lexical strings for string-declared arithmetic/count
Variables, and per-value string-to-integer conversion for int-declared split
Variables. Invalid split input (`1\nx`) produced a conversion warning and an
error result. OpenSCAP advertises OVAL 5.11.1, so this is evaluator behavior
 evidence, not independent OVAL 5.12.3 equivalence proof.

## Rule findings

| Rule | Function | Declared datatype | Function result | Finding |
|---|---|---|---|---|
| SV-274067 | arithmetic | string | integer/float | Requires numeric-to-string result conversion. |
| SV-271596 | arithmetic | string | integer/float | Requires numeric-to-string result conversion. |
| SV-258155 | arithmetic | string | integer/float | Requires numeric-to-string result conversion. |
| SV-215833 | split | integer | string collection | Requires per-value string-to-integer conversion; source-like config text fails. |
| SV-220544 | split | integer | string collection | Same. |
| SV-215688 | split | integer | string collection | Same. |
| SV-220596 | split | integer | string collection | Same. |
| SV-218771 | count | string | integer | Requires integer-to-string result conversion. |

The machine-readable file preserves the full source benchmark, Rule ID, source
hash, original Variable XML, function attributes/components, representative
success/empty/error values, and evaluator observations for every record.

## Native recommendation

Do **not** recover these Rules with the current grammar. A narrowly scoped cast
contract could be considered, but it requires owner approval. If approved, the
candidate representation should be explicit and typed, for example:

```yaml
function:
  name: cast
  arguments:
    - function:
        name: arithmetic
        arguments: [...]
        options: {arithmetic_operation: multiply}
  options:
    datatype: string
```

Required semantics would be: apply the cast to every value after the inner
function's Cartesian/collection evaluation; preserve order and duplicates;
produce an error for any lexical conversion failure; propagate error, unknown,
not-collected, not-applicable, and empty-population statuses without replacing
them with defaults; and use OVAL lexical rules for integer/float/string
conversion. This is only a proposal—not part of the canonical grammar or
converter.

The simpler alternative is to keep these Rules blocked as source datatype
mismatches. No cast decision is silently inferred from the OpenSCAP probe.
