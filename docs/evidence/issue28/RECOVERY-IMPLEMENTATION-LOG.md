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
to the existing native `null` representation when OVAL omits `datatype`.
The same explicit null boundary is covered for nullable Registry `key` and
`name` selectors. An explicit datatype is still checked exactly; wrong
datatypes, comparator-bearing nil nodes, non-empty nil nodes, and empty-string
values are not coerced. The capability position is the approved type for a nil
record, not a value-level inference.

## Typed-equality recursion

Windows file traversal now recognizes `equals` and the capability-supported
`case_insensitive_equals` selector forms as equality paths for downward
recursion. Pattern paths still reject recursion attributes, full paths remain
non-recursive, and upward/deprecated directions remain rejected. The .NET
Framework `SV-225229` source Rule is a focused corpus regression.

## Invalid path-pattern recursion

The seven source Rules previously blocked by OVAL-invalid `max_depth`, `recurse`,
or `recurse_direction` attributes on Windows pattern/full paths now use a narrow
native recovery. The selector and filesystem scope are preserved; only the invalid
recursion controls are removed, with source element identity, removed values, and
scanner-unproved status recorded under `oval_invalid_path_recursion_removed`.
No default filesystem traversal is fabricated, and the historical converter still
rejects the source shape. The rebuilt 65-benchmark ledger moves these 7 Rules from
blocked to automated-converted-unproved; this is not an independent semantic proof.

## Count

The recovery visitor now emits the canonical 0.4 function-call envelope
for one-or-more OVAL `count` components under the opt-in native recovery mode
and retains an inverse migration mapping. Extra operands are preserved rather
than silently counted as one. The pinned 0.4 schema snapshot used by the
current ledger does not yet admit that function in the Assessment Variable
schema, so count Rules remain **blocked pending canonical schema/compiler
admission**. Independent vectors now cover zero, empty-string, duplicate,
and error/unknown populations; no ledger count is presented as converted or
proved. The isolated semantic validator also enforces the owner-directed
three-function contract (numeric arithmetic widening, literal-delimiter split,
and signed-32-bit substring) when a future active schema admits it. It rejects
implicit string/number casts and malformed options; the pinned Assessment
schema still rejects these calls before semantic admission.

## Ordered float comparisons

The ten finite-float Rules now use an opt-in exact decimal-to-IEEE-754 binary32
converter aligned with the owner-coordinated SCAP-NG 0.4 contract. Existing
`float_*` comparison vocabulary is emitted without schema changes. Midpoint
ties, subnormal underflow, signed zero, overflow, malformed lexical forms, and
nonfinite expected values are covered by exact vectors. The original lexical
entity, contract identity/hash, and unproved scanner status are retained in
provenance. Runtime/compiler/scanner equivalence remains unproved.

## Stable blocker accounting

Aggregate primary blocker selection now uses an explicit owner-reviewed root-cause
priority only when a Rule has multiple schema-semantic diagnostics. This keeps the
mutually exclusive ledger stable across supported `jsonschema` and `referencing`
versions without changing source/capability diagnostic order. Raw per-Rule
diagnostics remain preserved; normalization affects only aggregate classification
and representative examples.

## Deliberately not normalized

Multi-component `unique`/`merge` now have an opt-in canonical function-call
candidate preserving every source component, but the active 0.4
Variable-expression schema/compiler does not yet admit that call form. They
remain explicit schema/compiler blockers rather than silently changing source
semantics. XCCDF relational Value constraints likewise need a native typed
Parameter/Input relation contract; an allowed-values list is not a substitute.

## XCCDF Value metadata

Equality-valued XCCDF Values that contain non-executable `<warning>` metadata
are now admitted by the existing allowed-value Input/Parameter adapter. The
warning is retained in the source Value XML provenance and is not interpreted
as a constraint. Relational Value operators remain blocked until the typed
relation contract is approved.

## Additional converter recoveries

- Benchmark-scoped XCCDF Value/Parameter and external-Variable/Input names now
  use source-ID digest suffixes only when readable descriptors collide. This
  prevents cross-Rule parameter overwrites while preserving stable names for
  shared source identities.
- Version-typed cmdlet acquisition parameters retain their declared version
  datatype instead of being rejected as non-string inputs.
- Shell-command acquisition accepts the explicitly mapped case-insensitive
  equality operation for command/shell inputs; pattern inputs remain regex
  acquisition values.
- Test-level `check_existence="none_exist"` now takes precedence over State
  matching. State controls are not executed, are retained in a provenance
  warning, and cannot affect the native absence result.

- Variable-source Object `var_ref` datatype/operation attributes are admitted
  only for the exact string/equality boundary and retained in a conversion
  warning; non-default typed or comparator-bearing references remain blocked.

## Legacy WMI and XCCDF Value recovery (candidate)

The coordinated candidate schema commit `919732d4c570b521edf82196a7694dfd8c27fe50`
adds typed numeric Input `constraints.relation` to the existing 0.4 contract.
The converter maps the five active XCCDF relational Value Rules without casts;
all five are now automated converted/unproved. The same candidate migrates
single-field legacy `wmi_*` projections to `windows.wmi.query` record results.
One active Rule is fully admitted; fourteen remain blocked at downstream scalar
record/function or Set boundaries. See `XCCDF-VALUE-CONSTRAINT-ADAPTER.md` and
`LEGACY-WMI-RECOVERY.md`.

The repinned schema family is
`6bf2fa369fd7b9a0153899ac25109af3e3f9aa59c0f4aa6bb3be1aebd5b14fa0`; the
semantic pack is regenerated and pinned in the tools candidate. The active
candidate ledger is 6,479 automated converted/unproved, 1,403 manual-only, 108
genuinely blocked, and 209 intentionally excluded (8,199 total). Independent
proof, compiler execution, and scanner equivalence remain unclaimed.
