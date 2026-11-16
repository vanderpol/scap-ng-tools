# Converter applicability inheritance handoff

The converter's source model now retains a per-item applicability context:
Benchmark, each Group ancestor (including nested Groups), and Rule-local
platform children. The levels are not flattened. Platform children at one
source item are recorded as an `any_of` set; the consumer combines ancestor
levels with `all_of`.

Every source `platform` retains its `idref` and normalized XML SHA-256. CPE
URI references and XCCDF platform IDs are distinct provenance kinds. A native
condition key points to that source identity only; it is not an invented
executable Assessment. If no pinned native mapping exists, promotion is held
and the RI must report applicability ERROR rather than FALSE.

The converter emits recursive native Groups and optional local applicability;
Rule-local applicability is omitted when absent. It does not add a synthetic
condition for an unrestricted Benchmark, Group or Rule. Profile selection is
kept in the existing profile trace and is independent of applicability.

`tests/test_applicability_inheritance.py` covers all four inheritance levels,
nested Groups and same-level OR semantics. The full 65-benchmark corpus was
not regenerated or republished. Existing broad converter qualification remains
required after the canonical schema and RI drafts are reviewed together.
