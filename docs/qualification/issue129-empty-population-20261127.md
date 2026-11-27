# Converter Issue #129 — empty-population provenance — 2026-11-27

The converter change is intentionally narrow. It does not rewrite source XML,
insert dummy empty strings, add guards, fabricate Items, or turn an empty
Variable into a scalar. The source identity and source expected semantics stay
in the conversion ledger; the RI owns the corrected native zero-population
runtime semantics.

## Pins

- Canonical SCAP-NG 0.4.1 reviewed draft head: PR #135 at
  `3023eeb6149c0064ce8c337cd955f95e98a5b778` (not treated as a final pin until
  the canonical change is merged and repinned).
- Tools current main: `d119f0d03e7e6dfe8ea52591364415c90adf4744`.
- Active schema pin remains the existing Tools `canonical-schema-pin.json`; no
  version bump or parallel grammar is introduced by this issue.

## Conversion disposition

- Typed empty literals retain their declared native datatype so an empty
  Variable can be validated without guessing from absent values; the RI then
  applies the finite `value_match` table (one_or_more/exactly_one false,
  none/every true).
- Aliases and `unique`/`concat` preserve the zero cardinality; `count` remains
  an integer result of zero.
- Collected `values` projections remain source-traced expressions. The
  converter does not turn a missing/empty/failed collection into a fabricated
  literal; completeness and status remain an RI/runtime responsibility.
- Untyped empty literals remain an explicit `ambiguous/empty` authoring hold.
  The converter cannot infer a datatype from zero values.
- Existing OVAL `regex_capture` behavior is unchanged: a nonempty source
  population with no capture still follows the existing empty-string function
  contract, while a shell no-match field is a complete zero-value collection.
  These are distinct cases and are recorded as an intentional compatibility
  distinction.

## Qualification

```text
.venv/bin/pytest -q \
  tests/test_issue129_empty_population_provenance.py \
  tests/test_variable_inference_candidate.py \
  tests/test_issue59_native_function_lowering.py \
  tests/test_converter_provenance.py
```

The focused suite verifies typed empty inference, aliases/functions/count,
explicit untyped-empty holds, and lossless collected-field conversion. The
17-Test canonical empty-population oracle is executed by RI
`runtimecore/TestCanonicalEmptyPopulationAssessment`; converter output is not
used as the expected-outcome oracle.

## Ubuntu/SCC boundary

The converter package does not establish SCC equivalence. The recovered Ubuntu
24 run used 194 rather than the corrected 195/195 source package and
namespace-scoped diagnostic authority. A same-source, same-package,
same-target, same-authority RI/SCC replay remains required after the RI
SV-270754 FALSE correction; any OVAL State divergence must remain explicitly
classified rather than rewritten in content.
