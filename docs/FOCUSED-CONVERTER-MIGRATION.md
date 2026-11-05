# Focused SCAP 1.4 → SCAP-NG 0.4 converter: portability checkpoint

**Scope:** Strict Rule-ID conversion, read-only benchmark inventory, and
qualified automatic benchmark authoring conversion. Draft admission, compiler,
independent source proof, scanner execution and corpus regeneration remain out of scope.

## Mechanism

This package began with 17 existing direct-converter Python runtime modules and
the active 0.4 capability activation JSON, copied **byte-for-byte** from
`vanderpol/scap-ng-research` commit
`d12a644f4607cdc9c9ada50e3a96d4fd0060c6d9`. A CI test pins the aggregate
SHA-256 of these 18 source files to
`893ca2bef18245d636b662d6d1536bfa1c2aa5643a62ab60d88dad986fb7c46d`
(sorted file name + NUL + exact bytes). The inventory pass introduced two
**audited source-path injection edits** to `v04_direct_converter.py` and
`v04_direct_inventory.py`, so descriptive capability names are resolved from
the same flat catalog as conversion. At that earlier inventory-only checkpoint,
the other 16 source files were byte-exact,
with aggregate SHA-256
`9b8cd16d4407706ad22d3f604d0cef6c9173fd31a67e4ecb968fdb1a4f71f282`.
The adapted 18-file runtime's aggregate SHA-256 is
`fcfa3ef00a083dc6510a8e1bd421b338d4c892fde59ab61d693ed60d957bc099`.
Tests pin both changed files individually and the unchanged set independently.

The new wrapper is deliberately separate from the frozen source engine:

- `scap_ng_tools.converter.direct04` imports only package-local source modules,
  validates the exact original SCAP ZIP hash and selected Rule IDs, and injects
  supported capability mappings from the explicit, immutable flat snapshot.
- `FrozenSchemaSnapshot` verifies 143 schema/metadata JSON files, the frozen
  aggregate hash, 34 root schemas, 242 references and 100 supported mappings.
  Logical schema identifiers continue to use `v0.4.0` while physical paths
  are flat `schema/`.
- The focused result undergoes Draft 2020-12 validation with a local registry
  of versioned `$id`s. No network resolution is allowed. Draft validity is
  distinct from independent semantic or runtime verification.
- JSON/YAML output and source traces are written to a new destination only,
  with a separate explicit `CONVERTED_UNVERIFIED` scope record.
- A requested `--verify`, `--compile` or `--draft` fails before
  creating output, rather than quietly changing proof/compiler semantics.
  `--inventory-only` and `--all-rules` are separately qualified modes.

The source engine retains its historical module imports while the wrapper
loads them from a checked package-owned directory and rejects collisions with
same-named external runtime modules. Relative imports and full distribution
normalization can be addressed in subsequent packaging review. The tools
package licenses project-owned source under Apache-2.0; the upstream SCAP
source/fixture is neither bundled nor relicensed by this migration.

## Parity evidence

The selected original Windows Server 2025 source ZIP is SHA-256
`2f46264b5fa21c8a033236121794ebe372314bf7458dac0aca4f81179fe7ece0`.

Selected Rules:

- `xccdf_mil.disa.stig_rule_SV-278139r1182083_rule`
- `xccdf_mil.disa.stig_rule_SV-278080r1180946_rule`

Both the original CLI and the standalone tools CLI produced six native
documents with SHA-256
`497ac2042ddefd126c9723f181d655b1d5d4c4fad441c3f986a4b77315584c69`
(canonical sorted JSON). Their **13 common output files**—six JSON documents,
six YAML renderings and the source trace—were byte-identical. The old CLI
also wrote a nondeterministic `metrics.json`; the new CLI instead writes a
scope record that explicitly refuses runtime or proof authority. The entire
original converter acceptance suite passed separately (11 tests).

CI runs the package test suite against the exact frozen canonical checkout and
the pinned original signed fixture, including an output-hash assertion and
fail-closed proof-mode test. **This validates these selected source cases,
not all capability acquisition or the whole regression corpus.**

## Whole-benchmark read-only inventory

The original and standalone inventory engines now agree exactly on four pinned
source archives: **535 discovered Rules**, with identical manifest and source
trace digests for every archive. The Windows Server 2025 CLI's
`coverage.json`, `coverage.md` and `source-trace.json` were also checked
byte-for-byte against the original. The inventory emits **zero native
Assessments** and has no proof or scanner execution authority.

The source fixture hashes, per-file Rule counts and golden manifest/trace
digests are recorded in [the fixture ledger](TEST-FIXTURE-PINS.md) and enforced
by CI. This inventory-only result remains a distinct read-only baseline;
it is **not** evidence that every Rule can be converted or scanned.

## Issue #28 native existence recovery — draft

The native 0.4 `item_requirement` contract maps OVAL `all_exist` to
`one_or_more`; no synthetic absent Items are introduced. The Issue #28 draft
converter records each recovered source Test's original attributes and source
hash in binding provenance. This is an authoring conversion only: it does not
claim scanner, compiler, or independent proof equivalence.

## Issue #28 native Input/Parameter recovery — draft

The same opt-in native recovery mode accepts only explicit XCCDF
`check-export` bindings to a matching `Value`: datatype, exact cardinality,
and allowed-value constraints are retained. Unsupported Value operators remain
blocked. Original external Variable/Value identities and the unproved runtime
binding warning remain in provenance.

## Automatic benchmark authoring conversion — separately qualified

The original 0.4 semantic passes were copied into `_v04_semantic/` and adapted
without importing historical-version modules. An offline generated pack holds
the 52 activated capability fragments, exact field/selector type contracts,
and eight source OVAL acquisition-behavior declarations. The pack is rebuilt
from official OVAL 5.12.3 at
`2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`, using byte-audited
generator helper copies from research commit
`d12a644f4607cdc9c9ada50e3a96d4fd0060c6d9`, then byte-compared in CI.
Pack SHA-256:
`b78c4db59da4cb2bad4f783e9562a5df9060de1a0e60f29ff4afceef8443ca70`.
Neither historical generators nor source XSD files are needed by the wheel.

Three of the original 18 runtime files now have audited changes: converter
callback, inventory mapping injection, and source behavior defaults. The
unchanged 15 have aggregate SHA-256
`6360a01e45b460c8fa9669b996fa1406e647c76f539bff990fa3e7ba30a7acdb`;
the adapted 18-file runtime has SHA-256
`157fbf09f424cac5d79c7ed0501863200f7d4ed4e015e6e2b3ff78ef97859e4a`.
The earlier hashes above describe the preceding inventory-only checkpoint.

| Original pinned source | Rules | Admitted | Blocked | Native docs |
| --- | ---: | ---: | ---: | ---: |
| Windows Server 2025 | 291 | 247 | 44 | 496 |
| Active Directory Domain | 36 | 15 | 21 | 32 |
| Amazon Linux 2023 | 187 | 118 | 69 | 238 |
| Windows Defender Firewall | 21 | 0 | 21 | 0 |
| **Total** | **535** | **380** | **155** | **766** |

All four native-document, source-trace and coverage digests match the original
public `--all-rules` CLI exactly. The Active Directory common JSON/YAML/trace/
coverage files also match byte-for-byte. Negative Object, comparison, Variable
and optional Input tests reproduce the original diagnostic path, validator and
message. Windows's **247** in original public CLI broken-reference mode
intentionally differs from 249 in a legacy unit test using different source
options; earlier proofs were not touched or rebaselined.

**Status: CONVERTED_UNVERIFIED.** This is an admitted automated authoring subset,
not complete Benchmark/manual/OCIL conversion, compilation, independent source
proof, scanner evaluation or a current vendor publication.

## Remaining work before repository rename

1. Qualify draft admission, compile and independent source proof separately;
   their runtime graphs must not be copied wholesale.
2. Keep the signed source fixture checkout pinned to the public NIWC library;
   replace the CI's **remaining research generator/oracle** dependency before
   privatizing that research repository.
3. Expand pinned integration cases across the accepted regression and boundary
   suite before asserting a complete converter release.
4. Migrate/editor-repin the external metadata pack exporter, which currently
   embeds the old source commit and monorepo paths in its manifest.

These gates are separate from scanner implementation documentation, which is
deferred until after the base tools/editor pipeline works.
