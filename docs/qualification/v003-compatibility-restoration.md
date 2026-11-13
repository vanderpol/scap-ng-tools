# 0.3 → 0.4 conversion compatibility restoration

Status: **draft, fail-closed; not yet full converter or RI equivalence**.
This is maintained in [Tools PR #55](https://github.com/vanderpol/scap-ng-tools/pull/55).

The 0.3 converter was not disposable reference code. Its proven
dependency-graph, resource-bound, Set/Filter/status and round-trip tests must
be reused in the 0.4 program. The native 0.4 grammar and frozen production
benchmark visitor remain authoritative for current output.

## Reused original 0.3 components (byte-identical)

| Origin in `vanderpol/scap-ng-research` | New location in Tools | Original/ported Git blob SHA-1 |
| --- | --- | --- |
| `tools/scap_upconvert_v003/conversion_budget.py` | `src/scap_ng_tools/converter/conversion_budget.py` | `1a07b5d032f0f0c5bca81ff3fe3619e9b07513a5` |
| `tools/oval_result_truth_tables.py` | `tests/reference_v003/oval_result_truth_tables.py` | `dcd513cb3c5d75a2ecab4fc2575a0adc3bf75915` |

The new standalone source adapter ports the earlier iterative worklist
and cycle checks. It follows attribute-based and text-backed OVAL
`object_reference`, `filter`, and `var_ref` edges. It uses the original
0.3 budget tracker to prevent unbounded dependency nodes/edges; hitting a
budget returns an explicit `conversion_resource_limit` error and cannot
emit a complete-looking partial Assessment. The default budgets are
implementation safety limits (**100,000 nodes / 500,000 edges**), not OVAL
language restrictions or benchmark policy. Deep valid graphs (1,500 nodes)
and deep cycles (1,250 nodes) have dedicated tests.

## Source semantics exported as conformance evidence

`scripts/export_v003_oval_source_truth.py` reads the **byte-verified**
original oracle and deterministically produces:

| Source behavior | Vectors |
| --- | ---: |
| Set collected-object flag propagation (UNION, INTERSECTION, COMPLEMENT) | 108 |
| Filter include/exclude with true/false/error/unknown/not-evaluated/NA | 12 |
| Existence and missing/error/not-collected populations | 40 |
| AND, OR, XOR, ONE aggregation for paired OVAL results | 144 |
| **Total** | **304** |

Every CI run tests the original oracle and its known decisive edge
cases, and regenerates these vectors. `tests/test_v003_oval_source_truth.py`
pins the expected behavior and source hash.

**IMPORTANT:** These are **OVAL-source truth expectations**. Their successful
generation does not prove 0.4 source conversion or the RI evaluator.
When the RI executes Set/Filter/evidence cases, its outputs must be
compared against these vectors and the original OVAL source. The
native result vocabulary may require an explicit status mapping;
unknown/error/not-collected must never be silently coerced to Boolean.

## Additional independent fail-closed source checks

The separate source XML reader in `scripts/audit_self_assertion_parity.py`
now discovers reachable Set operations and Filter actions through the
original Object/State/Variable reference graph. It rejects a supposedly
converted Assessment if its native authoring has silently dropped the
source UNION/INTERSECTION/COMPLEMENT or include/exclude semantics.

This is a **necessary retention check, not sufficient equivalence proof**:
Set operand order (especially COMPLEMENT), nested Filter placement,
duplicate evidence, population flags and type/Variable behavior still
require independent source/native semantic tests.

## Reproduction

```bash
python3 -m unittest discover -s tests -p test_unified_oval_conversion.py -v
python3 -m unittest discover -s tests -p test_self_assertion_parity.py -v
python3 -m unittest discover -s tests -p test_v003_oval_source_truth.py -v

python3 scripts/export_v003_oval_source_truth.py \
  --output /tmp/oval-source-truth-v003.json
```

These tests are mandatory in
`.github/workflows/oval-full-tree-parity.yml`. The original independent
`scap-ng-research/tools/scap_ng_roundtrip_v003/compare_oval_semantics.py`
is retained as a source for the next **test-only semantic proof port**.
It is not copied into production because 0.3 native YAML differs from
canonical 0.4 and blindly using its 0.3 reverse exporter would be misleading.

## Release blockade

The current full-content original has 168 Definition instances /
803 Tests, including embedded OVAL XML. The last measured candidate
generated 90 native Definitions; 78 remain blocked, with independent
parity holds requiring explanation. The full-generation workflow
**must remain red** until source and native semantics are proved for
every approved in-scope case. No incomplete corpus is the canonical
`main` release, and no RI/SCC equivalence is claimed by the source
fixture tests.

Next acceptance gates: recover native Variable Sets/Filters; compare
native source graphs against original Set/Filter/Variable AST and the
0.3 vectors; run the 65-benchmark primary+inventory/CPE audit; restore
the original independent OVAL round-trip proof against a 0.4-aware
reverse projection or differential runtime. Frozen benchmark visitor
and existing CI baselines remain immutable until a reviewed migration.
