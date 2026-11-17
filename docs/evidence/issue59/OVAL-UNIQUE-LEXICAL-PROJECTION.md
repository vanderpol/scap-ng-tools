# Source OVAL `unique` → native SCAP-NG 0.4.1 lexical projection (candidate)

## Problem

Native 0.4.1 `unique` preserves its input datatype. The pinned OVAL 5.12.3 `unique` function is documented in the exhaustive datatype inventory as yielding **string** values. A converter lowering the source function straight to native `unique: {values: ...}` therefore loses this type distinction when the collected field allows multiple datatypes. The active field pack exposes such permission explicitly (e.g. `independent.textfilecontent.subexpression`), and the conservative validator rejects the unresolved type. Making `string` the default type for all collected fields is prohibited.

## Candidate translation

For a **source OVAL `function: {name: unique}` envelope only**, project each *direct* collected-field `values` operand with a visible lexical conversion `concat: [{literal: ""}, <values>]`, then apply native `unique`. This leaves the native authored `unique` grammar and its datatype-preserving meaning untouched. It does not modify original OVAL XML, reorder or drop components, change source declarations, add a generic function envelope, or cast a typed literal or Variable alias whose behavior is not independently established.

The parser still rejects missing source components/options; typed mixed literals, unresolved aliases, unsupported record evidence and status propagation remain semantic holds. The new tests demonstrate syntax, idempotence, copy isolation, and bounded conversion placement only.

## Release qualification

This is **not** an equivalence proof. Source OVAL string conversion, cross-type equality/deduplication (especially lexical integer versus `"001"`, float/boolean/binary/version), order and first-occurrence selection, collection failures, incomplete/unknown/not-collected/empty evidence, and downstream Require/selector comparisons must be checked with pinned original OVAL and RI vectors. The full 65-source signed ZIP rebuild must provide exact Rule-ID transitions; do not report projected recoveries as conversions until that workflow completes. Preserve the release nonregression FAIL/HOLD until all original converted IDs are retained.

Canonical 0.4.1 schema changes, editor metadata, RI behavior and publication pins are out of scope. This candidate is stacked on Tools PR #63 and remains DRAFT.
