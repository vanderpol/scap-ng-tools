# Independent coordinated binary32 review — 2026-11-03

**Hold merge.** This review found one reproducible implementation blocker,
C1 below. All12 PRs in the dependency graph remain draft/unmerged; the three
primary PRs have zero formal review submissions/threads. No merge, retarget,
force-push or change to the reviewed heads was performed. This is a technical
audit with fresh witnesses, not independent human acceptance.

## C1 — accepted API-record float predicates evade the contract (high)

At native PR278 `855c6023d55d882b55c0507d5492e6f4e4946023`, a schema-valid
`windows.cmdlet` Test can contain:

```json
{"parameters":{"fields":{"Threshold":{"float_equals":1.25,"selection_match":"one_or_more"}}}}
```

The complete [reproducer](../scripts/review_binary32_record_gap.py) uses a
synthetic presence-only Assessment; no real cmdlet/provider is executed.
Both producer and independent consumer return empty float inventories, and the
program is emitted as **program/0.1 without a binary32 binding**. Noncanonical
expected `1.2` is also accepted with zero structural/semantic validation errors.
[Exact witness output](evidence/issue14-absence/binary32-record-gap.json).

The producer examines scalar selector domains but omits the grammar under
`collection_parameters` with `schema_ref: object_record`. The independent reader
explicitly skips that same site. The portable overlay has the corresponding
omission. These `parameters.fields` and `select.fields` predicates are executable
argument/selection grammar, distinct from opaque literal record data. Both
schemas and the existing version1 contract permit the six self-describing float
operators there; the contract does not exempt this context.

Before merging, bind these predicates in producer/portable validation/independent
reader, or fail closed where the profile cannot be honored. Test canonical and
noncanonical literals, arrays/references, nested Object sites, both parameters
and select, missing/downgraded inventories and opaque literal records. Do not fix
coverage by traversing arbitrary data dictionaries. This is an implementation
coverage defect in the approved contract, not a request for new float semantics.
The review leaves the original PR heads intact for an isolated follow-up fix.
Findings were posted on PR278 and Tools PR19.

The ten previously qualified source cases use scalar State fields. Their narrower
native/number receipts are preserved; they do not establish API-record coverage.
Existing green tests and rehashed inventory mutants missed the shared traversal
gap and therefore cannot support a blanket all-grammar precision claim.

## Contract, pins, compatibility and evidence checked

| Repository / PR | Exact reviewed head | Base dependency |
| --- | --- | --- |
| canonical13 | `da4c48dfc60dc96a46e7b85425f70fb8f301a0b1` | canonical11 `246a8d37cc54875386768a7d76b60a6f9c01d013` |
| native278 | `855c6023d55d882b55c0507d5492e6f4e4946023` | native275 `7e26f8da44a81ae96135eca837e611a3f99f9c28` |
| tools19 | `23eea6462cfa0ae2bd3321985d16a07ac36a03f1` | tools18 `688a71896cac03dad3a5664d1e8d500866ac1fa2` |

[The complete12-PR audit](evidence/issue14-absence/binary32-stack.json) records
every branch/base/head, draft/merge state and exact-head CI run. Current main refs
were independently read from Git. Canonical main is `c6414084`; tools main is
`7fe944a3`; native main is `fc62031c`, two commits beyond the root's reported
`d12a644f` base. Read-only `git merge-tree` found no textual conflicts for the
full native stack against current main; virtual tree
`f024ccd2768dffd4692cf6aa7bea7dd00059abe6` is **not a tested integration tree**.
No branch/index was merged or updated by that check.

The version1 descriptor's bytes/hash
`676dfd1bbe1e83e781e68c9c66fd4e53ed6f9da4278affbd0a877edf49ab03dd`
agree between canonical and native, and the two reference helper copies agree.
The intended domain is finite canonical binary32 expected values, direct source
decimal rounding, signed zero/subnormals/overflow and lexical errors. Nonfinite
expected/Result representation and arithmetic/scanner execution remain deferred.
Typed references carry a runtime finite/canonical invariant; compilation is not
evidence that such runtime values have been supplied or evaluated.

All143 schema JSONs/family `f19246c6...` remain unchanged by canonical13, with100
mappings/34 roots/244 references. The descriptor is outside that frozen family
and is checked separately. Source conversion opts in with an exact sidecar;
the two CI schema checkouts deliberately preserve the old exact235-resource
Editor metadata proof. No Editor36 changes are required or authorized here.

Old non-float program formats/bytes and strict535 Rule goldens remain covered by
the existing tests. Historical float programs must use their pinned prior
toolchain or explicit recompilation; old consumers must reject program/0.4.
No source pin, manual Assessment, legacy0.3 schema or historical proof is changed
by this review. The absence successor adds only the separately authorized source
correction described in its own packet.

Evidence was read at exact reviewed heads: canonical CI41664336667 passes18
tests/documentation bytes; Tools CI41673398105 passes77 tests/zero skips plus
semantic-pack byte audit and foundation41673398054 is green. Native schema
41672578177 passes257 tests; native fast41672578808 executes318 tests then fails
quota upload. Clean-extract41672578478 executes successfully then fails retention
upload. Required six uploads fail in41672578872 and aggregate validation/compile
is skipped; Windows/Linux later tails in41672578702 are blocked by earlier
uploads. These workflow conclusions remain failed/skipped, not green. The prior
local full six receipt is retained at its actual head; no upload was retried.

## Conditional safe merge order

No merge is recommended now. Resolve C1, review the amended exact heads, refresh
all dependent compiler/contract pins and receipts, and complete required gates
under project policy before considering integration. Direction approval and
machine-green do not replace human acceptance. The conservative topological
order is:

1. Canonical **9 →11 →13** (discovery, functions, binary32 contract).
2. Native **272 →275 →278 plus C1 correction** (source discovery, functions,
   compiler/consumer binary32 binding). Reconcile the two current-main commits
   and qualify the actual integrated tree; textual mergeability is insufficient.
3. Tools **13 →15 →16 →17 →18 →19 plus portable C1 correction**, then the
   focused absence successor. Each native-producing feature follows its contract
   and consumer support. Earlier narrower stages can be integrated separately
   only with their own dependency closure and exact receipts.

Prefer preserving reviewed commits. A squash/rebase or changed descriptor/code
head requires deliberate repinning and fresh affected qualification; it must not
silently substitute a moving `main` for an immutable pin. Native CI-retention
PR277 is a separate policy review; it is not merged/cherry-picked here to bypass
artifact gates. Editor36, release preparation, full65 and mandatory six-transfer
workflows are outside this work.
