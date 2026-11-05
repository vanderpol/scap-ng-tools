# Issue #28 recovery implementation log

This log records converter changes that were admitted only after source-backed
fixtures and pinned-schema ledger runs. It does not promote any Rule to
independently proved.

## Identity collisions

Readable comment-derived identifiers now receive the first ten hexadecimal
characters of the source-ID digest when the same `(kind, native identifier)`
would otherwise identify two source nodes. The discriminator is deterministic,
keeps the 64-character limit, and the complete source identity remains in the
Rule binding. The Office 365 `SV-223296` pair is the corpus regression.

## Nil selectors

`windows.cmdlet` record-valued nil inputs (`parameters` and `select`) now lower
to the existing native `null` representation when OVAL omits `datatype`. An
explicit datatype is still checked exactly; wrong datatypes, non-empty nil
nodes, and empty-string values are not coerced. The capability position is the
approved type for a nil record, not a value-level inference.

## Typed-equality recursion

Windows file traversal now recognizes `equals` and the capability-supported
`case_insensitive_equals` selector forms as equality paths for downward
recursion. Pattern paths still reject recursion attributes, full paths remain
non-recursive, and upward/deprecated directions remain rejected. The .NET
Framework `SV-225229` source Rule is a focused corpus regression.

## Count

The recovery visitor now emits the canonical 0.4 function-call envelope for a
single-operand OVAL `count` function under the opt-in native recovery mode and
retains an inverse migration mapping. The pinned 0.4 schema snapshot used by
the current ledger does not yet admit that function in the Assessment Variable
schema, so count Rules remain **blocked pending canonical schema/compiler
admission**. No ledger count is presented as converted or proved.

## Deliberately not normalized

Multi-component `unique`/aggregation has no approved native collection-union
expression in the pinned contract. XCCDF relational Value constraints likewise
need a native typed Parameter/Input relation contract; an allowed-values list
is not a substitute. Both remain explicit blockers rather than silently
changing source semantics.

## XCCDF Value metadata

Equality-valued XCCDF Values that contain non-executable `<warning>` metadata
are now admitted by the existing allowed-value Input/Parameter adapter. The
warning is retained in the source Value XML provenance and is not interpreted
as a constraint. Relational Value operators remain blocked until the typed
relation contract is approved.
