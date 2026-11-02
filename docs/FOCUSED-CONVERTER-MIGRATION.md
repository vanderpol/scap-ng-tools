# Focused SCAP 1.4 → SCAP-NG 0.4 converter: portability checkpoint

**Scope:** Source-backed strict Rule-ID conversion only. No full benchmark
conversion, draft admission, compiler, independent source proof, scanner
execution or corpus regeneration is represented as complete.

## Mechanism

This package began with 17 existing direct-converter Python runtime modules and
the active 0.4 capability activation JSON, copied **byte-for-byte** from
`vanderpol/scap-ng` commit
`d12a644f4607cdc9c9ada50e3a96d4fd0060c6d9`. A CI test pins the aggregate
SHA-256 of these 18 source files to
`893ca2bef18245d636b662d6d1536bfa1c2aa5643a62ab60d88dad986fb7c46d`
(sorted file name + NUL + exact bytes). The inventory pass introduced two
**audited source-path injection edits** to `v04_direct_converter.py` and
`v04_direct_inventory.py`, so descriptive capability names are resolved from
the same flat catalog as conversion. The other 16 source files are byte-exact,
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
- A requested `--verify`, `--compile`, `--all-rules` or `--draft` fails before
  creating output, rather than quietly changing proof/compiler semantics.
  `--inventory-only` is a separately qualified, read-only mode.

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

CI runs the package test suite against the exact frozen staging checkout and
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
by CI. This establishes a dependable inventory baseline before benchmark-wide
conversion is migrated; it is **not** evidence that every inventory entry can
be converted or scanned.

## Remaining work before repository rename

1. Review and migrate active benchmark-wide conversion, compile and independent
   proof modules and their expected artifacts without importing historical
   experimental dependencies wholesale.
2. Replace the CI's source fixture checkout from the soon-to-be-private
   research repository with a license-reviewed, pinned fixture distribution.
3. Expand pinned integration cases across the accepted regression and boundary
   suite before asserting a complete converter release.
4. Migrate/editor-repin the external metadata pack exporter, which currently
   embeds the old source commit and monorepo paths in its manifest.

These gates are separate from scanner implementation documentation, which is
deferred until after the base tools/editor pipeline works.
