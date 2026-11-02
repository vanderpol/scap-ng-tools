# Direct 0.4 converter: flat-schema compatibility gate

**Status: focused conversion, read-only benchmark inventory and automatic
benchmark authoring conversion migrated with exact original output parity.
Draft admission, compile and independent verify remain pending. Not a complete
converter release, canonical repo rename authorization or scanner proof.**

The original `vanderpol/scap-ng` 0.4 converter is currently a monorepo tool.
`v04_direct_converter.py` loads mapping records and JSON Schema definitions
from its own checkout's `schema/v0.4.0/`. The future canonical specification
checkout instead stores its frozen files in flat `schema/` and will be renamed
from `vanderpol/scap-ng-staging` to `vanderpol/scap-ng` only after cutover checks.

## Contract established here

- Consumers explicitly select the full canonical checkout or its flat
  `schema/` directory. No GitHub network lookup, floating `main`, inherited
  working-directory fallback or bundled copy of the schemas is permitted.
- The `FrozenSchemaSnapshot` reader fails on legacy nested layouts, altered
  bytes, incorrect logical IDs, unexpected reference counts, missing mappings,
  bad capability names and duplicated source JSON keys.
- The frozen 143-file aggregate SHA256 is
  `476f5767276f5c2114f91b211cf4e159a75bee0806ea736fc631d9c40f4c4b80`.
  The logical `$id` URIs still contain `v0.4.0`, independently of physical paths.
- The external probe imports an **explicitly pinned legacy source checkout**,
  produces the original direct converter's output and trace, substitutes only
  the source of its 52 mapping records, and requires identical native output.
  It validates the result against the flat schema. No source file is changed.
- CI checks out the exact staging merge commit above into a separate directory
  and runs the schema adapter tests against it. The staging repository name
  in that workflow must be updated during the owner-controlled name cutover;
  the pin cannot be silently changed to floating `main`.
- A separately reviewed migration copies the focused direct converter engine
  initially byte-for-byte into this package, keeping schema resolution and
  output writing outside the source engine. Two small documented inventory
  catalog injection adaptations are now pinned by test. See
  [focused migration](FOCUSED-CONVERTER-MIGRATION.md). The signed CI fixture
  checkout now pins the public NIWC **Archive/2026_Q3/** directly, preserving
  the four exact Git blobs and SHA-256 ZIP digests. `Current/` is a moving
  quarterly release pointer, not the regression fixture path. The research checkout
  remains **only** for the build-time generator and independent source oracle.

The separately audited automatic benchmark mode uses an offline 0.4 semantic
contract pack generated from the pinned OVAL XSD/generator and the unchanged
flat metadata, byte-regenerated in CI. This removes research/XSD runtime
dependencies without weakening structural, Object, comparison, Variable or
Input admission. The four original acceptance ZIPs produce **380 admitted,
155 blocked Rules and 766 native documents** with exact original document,
trace and coverage hashes. This remains `CONVERTED_UNVERIFIED`; no compiled
programs, source proofs, scanner evidence or new corpus publications result.

## Pinned Windows Server 2025 probe

Prerequisites are an *already locally available* clone of the original
SCAP-NG research checkout at `d12a644f4607cdc9c9ada50e3a96d4fd0060c6d9`, a
clean flat staging checkout at `ed4a9dce01af6849bf4be146c7678ef7804051e4`,
and the signed ZIP fixture from the research checkout. Install pinned test
dependencies for the original converter in the test environment. The source
ZIP SHA256 below is separately verified by the probe; the tool never fetches it.

```sh
PYTHONPATH=src:/path/to/research/tools python scripts/verify_flat_converter.py \
  --converter-root /path/to/research \
  --converter-commit d12a644f4607cdc9c9ada50e3a96d4fd0060c6d9 \
  --schema-root /path/to/pinned-staging \
  --source-package /path/to/research/tests/fixtures/v04-direct-prototype/server2025-signed.zip \
  --source-sha256 2f46264b5fa21c8a033236121794ebe372314bf7458dac0aca4f81179fe7ece0 \
  --rule xccdf_mil.disa.stig_rule_SV-278139r1182083_rule \
  --rule xccdf_mil.disa.stig_rule_SV-278080r1180946_rule \
  --expected-native-digest 497ac2042ddefd126c9723f181d655b1d5d4c4fad441c3f986a4b77315584c69
```

The pinned comparison covers **two Rule closures, 52 mapping records and six
native documents**, with zero schema validation findings. The source converter
acceptance suite (11 tests) also passed in the original repository. Neither
result proves all 100 supported capabilities, larger regression corpora,
scanner collection, compile/proof equivalence or the entire converter stack.

## Remaining cutover gates

1. Qualify the **remaining** direct converter modes and their runtime/proof
   dependency closure. The full compile/verify import graph still contains
   research modules and must **not** be copied wholesale without review.
2. Qualify draft admission and broader original regression coverage while
   preserving the now-pinned benchmark conversion output and without silently
   downgrading `--verify`/`--compile` semantics.
3. Migrate the editor metadata pack exporter and external tests to the flat
   snapshot. Its manifest includes a source commit, so changing repositories
   requires a deliberate pin/hash update even if schema bytes are identical.
4. Keep the signed-source fixture checkout pinned directly to public NIWC data.
   Relocate or replace the **remaining CI original converter/XSD oracle** before
   the research repository becomes private; review notices/licenses first.
   Expand regression and boundary tests against the new layout.
5. Only after the above gates pass: owner-controlled repository rename, link
   audit, release pin and external VS Code PR tasking.

Scanner implementation prose remains deferred; this checkpoint only establishes
offline schema contract resolution and a reproducible conversion comparison.
