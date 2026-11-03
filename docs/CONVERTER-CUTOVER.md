# Direct 0.4 converter: flat-schema compatibility gate

Scope note: this records the strict compatibility lane. The separate [Issue14
bounded recovery lane](ISSUE14-RECOVERY.md) now has its own current-DRAFT tests
and receipts; no historical hash/count below is redefined.

**Status: focused conversion, read-only benchmark inventory and automatic
benchmark authoring conversion migrated with preserved admission, source-trace
and coverage parity. Native bytes were deliberately regenerated for the
owner-approved pre-release 0.4 `item_requirement` grammar amendment.
Draft admission, compile and independent verify remain pending. Not a complete
converter release or scanner proof; canonical repository rename is complete.**

The original `vanderpol/scap-ng-research` 0.4 converter is a preserved research
monorepo tool.
`v04_direct_converter.py` loads mapping records and JSON Schema definitions
from its own checkout's `schema/v0.4.0/`. The canonical public specification
repository `vanderpol/scap-ng` (formerly staging) stores the identical frozen
0.4 files in flat `schema/` at historical pin
`ed4a9dce01af6849bf4be146c7678ef7804051e4`; the current amended candidate
is [canonical PR #4](https://github.com/vanderpol/scap-ng/pull/4) at
`354c9c962c77488a3d939cab56f6ceecfd495d27`.

## Contract established here

- Consumers explicitly select the full canonical checkout or its flat
  `schema/` directory. No GitHub network lookup, floating `main`, inherited
  working-directory fallback or bundled copy of the schemas is permitted.
- The `FrozenSchemaSnapshot` reader fails on legacy nested layouts, altered
  bytes, incorrect logical IDs, unexpected reference counts, missing mappings,
  bad capability names and duplicated source JSON keys.
- The amended 143-file aggregate SHA256 is
  `ab1933f2d9171ee0af70c0fab855b00f5faf78bf59ad4924fbf24b402ac4072a`;
  the previous frozen digest was
  `476f5767276f5c2114f91b211cf4e159a75bee0806ea736fc631d9c40f4c4b80`.
  The logical `$id` URIs still contain `v0.4.0`, independently of physical paths.
- The external probe imports an **explicitly pinned legacy source checkout**,
  produces the original direct converter's output and trace, substitutes only
  the source of its 52 mapping records, and requires identical native output.
  It validates the result against the flat schema. No source file is changed.
- CI checks out the exact canonical schema commit above into a separate
  directory and runs the schema adapter and 100-capability editor-pack tests
  against it. The checkout name is now permanent and the commit remains
  pinned, never floating `main`.
- A separately reviewed migration copies the focused direct converter engine
  initially byte-for-byte into this package, keeping schema resolution and
  output writing outside the source engine. Two small documented inventory
  catalog injection adaptations are now pinned by test. See
  [focused migration](FOCUSED-CONVERTER-MIGRATION.md). The signed CI fixture
  checkout now pins the public NIWC **Archive/2026_Q3/** directly, preserving
  the four exact Git blobs and SHA-256 ZIP digests. `Current/` is a moving
  quarterly release pointer, not the regression fixture path. CI no longer
  checks out the research repository: it regenerates the 52-capability pack from
  the pinned official OVAL 5.12.3 source and audited generator-helper copies,
  and checks the original converter's frozen document, trace, coverage and
  CLI-byte goldens. An optional original CLI differential probe remains.

The separately audited automatic benchmark mode uses an offline 0.4 semantic
contract pack generated from the public pinned OVAL XSD and source-audited
generator helpers, along with the unchanged
flat metadata, byte-regenerated in CI. This removes research/XSD runtime
dependencies without weakening structural, Object, comparison, Variable or
Input admission. The four original acceptance ZIPs produce **380 admitted,
155 blocked Rules and 766 native documents** with new owner-amended document
hashes and unchanged original trace and coverage hashes. This remains
`CONVERTED_UNVERIFIED`; no compiled
programs, source proofs, scanner evidence or new corpus publications result.

## Historical original Windows Server 2025 differential probe

The command below is retained as the **pre-amendment oracle** for exact
research output. It is not a current 0.4 schema test after Item regrouping;
use CI or `tests/test_focused_converter.py` against canonical PR #4 for current
output. The reviewed new six-document digest is
`8beb7b1c31c6321aa24ef4a0cfbbdd900dcd6dc349c8963887a9db28ee04d493`.

Prerequisites are an *already locally available* clone of the original
SCAP-NG research checkout at `d12a644f4607cdc9c9ada50e3a96d4fd0060c6d9`, a
clean flat canonical checkout at `ed4a9dce01af6849bf4be146c7678ef7804051e4`,
and the signed ZIP fixture from the research checkout. Install pinned test
dependencies for the original converter in the test environment. The source
ZIP SHA256 below is separately verified by the probe; the tool never fetches it.

```sh
PYTHONPATH=src:/path/to/research/tools python scripts/verify_flat_converter.py \
  --converter-root /path/to/research \
  --converter-commit d12a644f4607cdc9c9ada50e3a96d4fd0060c6d9 \
  --schema-root /path/to/pinned-canonical-scap-ng \
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
3. **Editor-pack exporter qualification is complete for the owner amendment:**
   all 235 resources match the reviewed amended 100-capability pack, and a
   new manifest/sourceCommit is pinned and tested. Now repoint the editor
   profile and its CI to the canonical repo in a separate reviewed change.
4. Keep the signed-source fixture checkout pinned directly to public NIWC Q3
   archived data. CI's old-research checkout has been replaced with a pinned
   public OVAL build-time input, exact original CLI goldens, and byte-copied
   generator helpers. Keep the optional local research differential check
   available to owners, and review notices/licenses and expanded edge cases.
5. The owner completed canonical/research repository renames and privacy
   cutover on 2026-11-02. Finish the reference/link audit, editor profile pin,
   and editor CI before external VS Code Codex tasking. Converter proof and
   release qualification remain separate future work.

Scanner implementation prose remains deferred; this checkpoint only establishes
offline schema contract resolution and a reproducible conversion comparison.
