# Unified OVAL conversion architecture — SCAP-NG 0.4

**Status:** draft architecture implemented in Tools PR #55, not released.
The converter is not fully qualified for all Self-Assertion source Definitions.

## Single interpretation engine

Two source ingestion formats, ONE typed native conversion engine:

```text
SCAP 1.4 datastream / benchmark             Standalone OVAL Definitions XML
  XCCDF Rule -> OVAL check                     Definition -> Criteria
             |                                         |
       SourceModel adapter                    StandalonePlatformSource adapter
             +---------------------+-------------------+
                                   |
              v04_direct_converter.AssessmentConverter
                capability mapping + Object + State
                Variable graph + predicates + Evaluate
                                   |
                      canonical 0.4 Assessment
                                   |
           same JSON Schema + semantic validation gates
                                   |
                 JSON / YAML + source identity trace
```

**Invariant:** The `_v04_runtime/v04_direct_converter.py` copied core is
byte-identical to its reviewed baseline and protected by the frozen-copy
hash test. The standalone adapter does not define a second Variable
evaluator, a per-platform Test allowlist, or independent native output
semantics. It sets `native_recovery=True` on a visitor instance only;
benchmark entry points retain their current explicit/default flags.

Primary APIs:

- `convert_focused` — selected benchmark Rules, exact pinned original ZIP.
- `convert_benchmark` — all benchmark Rules and original disposition ledger.
- `convert_oval_definition` — one original standalone Definition, pinned
  XML hash, Git commit, repository path, same visitor and validation.
- `convert_self_assertion_corpus.py` — deterministic source-tree
  orchestration, not a translation engine. It operates over every
  platform directory and explicitly inventories embedded XML archives.
- `audit_self_assertion_parity.py` — separate original-XML reader and
  independent source-to-native identity/cardinality/AST check. Does not
  use native content as the source of truth.

The legacy `oval_variables.py` now reexports the common adapter for
backward-compatible imports. **Do not add conversion logic there.**

## Release gate — all original content

Pinned original source:
`OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`.

Independent original inventory: **144 standalone XML files + one OVAL
Definitions XML inside a ZIP = 168 Definitions / 803 Tests**.
The ZIP input has 18 Tests not present in the standalone-only 167/785 count.
Supporting ZIP/TAR members must be inventoried and classified, not
silently treated as converted OVAL Definitions.

Prior standalone 0.4 adapter converted 9/168 Definitions (72/803 Tests).
The unified production visitor's early run converted 90/168 (442/803)
with all generated JSON/YAML schema-validated. **This is not a full
release; 78 Definitions remain blocked and 37 independent structural
parity investigations remain** at that checkpoint.

To publish the single canonical version on `main`, require ALL of:

1. Every original Definition/Test accounted for using (source path, ID),
   exact pinned Git/source hash, source graph, and independently rebuilt
   manifest; all supported native capability cases converted.
2. Every admitted native Assessment validates against one approved,
   **current** canonical 0.4 schema family and semantic pack, with
   duplicate-key rejection, both JSON/YAML representations, identical
   data on round-trip, and byte-identical repeat builds.
3. Independent OVAL/XML vs SCAP-NG authoring parity for Test identities,
   recursive extended criteria, source Object/State/Variable closure,
   datatypes, operations, filter/Set semantics, comparison cardinalities,
   literal values/order/duplicates, and complete provenance. Unknown
   constructs fail closed.
4. Successful compiled RI execution of converted source on matching
   synthetic/real environments, including true/false/unknown/error,
   existence/filters, and resource-bounded stress. Independent SCC
   differential execution where SCC supports the source case. Do not
   substitute schema validation for executable equivalence.
5. Unavailable platform semantics require exact source-linked, explicit
   owner approval of exclusion, or a coordinated canonical schema,
   collector and evaluator implementation. Source inventory *accounted*
   does **not** mean all automated Tests converted.
6. Benchmark regression gates pass at the same exact converter commit.
   No change to frozen converter bytes or benchmark goldens solely to
   satisfy standalone conversion.
7. One immutable canonical release manifest/alias and one deterministic
   regenerate command published on `main`. Downstream RI and VS Code
   must pin this exact source/schema/output SHA; historical snapshots
   remain immutable. Draft/old partial corpora must not be made the
   active default.

## CI meaning

- **Full-tree source parity audit PASS:** source checkout/inventory and
  audit fixture tests execute. It is NOT a release statement.
- **Full converter regeneration FAIL:** correct while any original
  Definition remains blocked or independently inconsistent.
- **Authoring/frozen-schema PASS:** benchmark converter regressions
  remain guarded. Required before any promotion.
- **RI/SCC result equivalence:** separate unfulfilled qualification.
- **Release-ready:** only when ALL gates above have exact-head receipts.

Do not merge or change `main` simply because source accounting or
native JSON Schema validation passes.
