# Pinned SCAP 1.4 benchmark inventory fixture ledger

These are **source-frozen compatibility inputs**, not a claim that upstream
vendor content is the latest publication, that all findings can be converted,
or that any target host has been scanned. The corpus was originally pinned from
`niwc-atlantic/scap-content-library` revision
`8c8e5dff860af6b1290ee9273a282db24278f8d5` and is referenced through
`vanderpol/scap-ng` research commit
`d12a644f4607cdc9c9ada50e3a96d4fd0060c6d9`.

Each signed fixture is retrieved directly from the **public NIWC Q3 2026
archive** (`Archive/2026_Q3/`) at that exact commit into a separate temporary
CI checkout. It is neither
embedded in the tools wheel nor distributed under this repository's Apache-2.0
license. CI verifies the source ZIP SHA-256 before reading it. The original
research repository is no longer checked out by CI: the historical converter's
native/trace/coverage digests and CLI file-byte inventory are immutable goldens,
and the original generator helpers are audited source copies.

| Fixture / suite | ZIP SHA-256 | Original Rule count |
| --- | --- | ---: |
| `server2025-signed.zip` / `v04-direct-prototype` | `2f46264b5fa21c8a033236121794ebe372314bf7458dac0aca4f81179fe7ece0` | 291 |
| `U_Active_Directory_Domain_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip` / `v04-draft-compatibility` | `94740b7929dd868043ab1b476c3b568712fc26d045a4d450359cea90effbfa1c` | 36 |
| `U_Amazon_Linux_2023_V1R2_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` / `v04-draft-compatibility` | `88cc35f98c9ff96c567110c284c06e6adfc556fd59967019bdec6fd1cc5a204f` | 187 |
| `U_MS_Windows_Defender_Firewall_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV14-signed.zip` / `v04-draft-compatibility` | `d16c868152e14bab0a1e2ecdfa6ec889972e068625d4d20d4ac3f861ff2009ca` | 21 |

**Total: 535 unique Rule entries across four benchmark inventories.**

The repository's `Current/` and `Archive/2026_Q3/` trees are **identical** at
the pinned revision: Git tree
`144371b737af54d39cb51389a21f1bdcb14c2132`. CI deliberately reads the
archived Q3 paths, never the moving `Current/` alias. Exact original Git blobs:

| Source | Pinned public Git blob SHA-1 |
| --- | --- |
| Windows Server 2025 (public original filename `U_MS_Windows_Server_2025_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip`) | `f6ba90413cd8a6ab3f9f5acc82603d9b52aca9cf` |
| Active Directory Domain | `fbe644f2211fbd3df5643bffb535bb4a477e07ac` |
| Amazon Linux 2023 | `60c5fe6e02dd5defa0f2ce64fcbb0abe7e0c809c` |
| Windows Defender Firewall | `4380631f9847892fd01afa7ce9c3d568ce0bcd06` |

## Exact original-to-tools comparison

The output digests below are SHA-256 of deterministic `json.dumps(...,
sort_keys=True)` serialization. They are asserted in
`tests/test_benchmark_inventory.py` against the original converter's pinned
manifest and source-trace output. No result rebaseline is permitted implicitly.

| Source | Inventory manifest SHA-256 | Source trace SHA-256 |
| --- | --- | --- |
| Windows Server 2025 | `b8e006eceeaca1d1e669e88d2f9336ea3ad165323409a2ff49f80e0641e9b238` | `2350f42616db168fd7984af6f28fea19e3538bb91e0c2dd6fa477e6f2f5d1126` |
| Active Directory Domain | `9335f772f3cc5a1952c46d66b1087f17dbd2105ce975b4f9156f29fc96d8d719` | `19f8df8e2e7d714bee02bb03334323ef4e19087e0d28d9e8cb0621e9f96bebfb` |
| Amazon Linux 2023 | `6b3cdccfda5097f549f7372ae95c661f88b03d2097e9ebce366c4d99e31d0823` | `3f82c57c8a34a5055a342993dfa496d62e653d1d83f159dc721799b50f576786` |
| Windows Defender Firewall | `f0ba480d3e3d2c61600e68cc1e34daecfc8fe90804912bde5b4484f4440921b4` | `5a9c179c112065435380c84fcd79fe83830d215e2f3f72550094777feb72fe9c` |

The separate focused conversion baseline remains six native documents from
the two selected Windows Server 2025 Rules, with canonical native SHA-256
`497ac2042ddefd126c9723f181d655b1d5d4c4fad441c3f986a4b77315584c69`.
Inventory is read-only and does not establish authoring admission or proof.

## Pinned automatic authoring-conversion admission

These are the original public `--all-rules` CLI outputs, independently computed
from the same four signed source ZIPs with the original 0.4 semantic validators.
Both the installed converter and the source oracle must match all three hashes.
Hash construction is the same canonical sorted JSON serialization as above.

| Source | Admitted / blocked | Native docs SHA-256 | Automatic coverage SHA-256 | Automatic source trace SHA-256 |
| --- | --- | --- | --- | --- |
| Windows Server 2025 | 247 / 44 | `c817e8b1842cecc20fa6174551502cd2199d8ddb9019214e432f9108c193a496` | `233fa961e84f101107cb62c5b810aa4719309c8bb5c31bbe2e212a09676c5bf4` | `2b06986ff6c21ea65a0a6ee45acacf53bdd58e96925ad84be47ae39765fa1e1c` |
| Active Directory Domain | 15 / 21 | `7b4035676c5b5aed43a2f3c0e6dfe92b40661c6e66de9e8d12eff322e68e8cd3` | `f90aacf66975f5d3cadf4d1d941142ad2a40f8c6a4c682eab491e15b2e604a53` | `db1dbdcbf11065eb14cad93afcd90004e12f82b4012e2423ce5b3068ab5766b5` |
| Amazon Linux 2023 | 118 / 69 | `5d3d4e176efed970984a60ce693a740aa0e23d767dd16041c276654cbac2ca58` | `da41d34d4c1b307097cb55c93e700e4bfa3f85950485c189d6f2f22a9f67a375` | `2d21ab8b6690f74023cf3b4f14f68164a9528b52e71196b8f7b9043c84b6467a` |
| Windows Defender Firewall | 0 / 21 | `44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a` | `5e70d08b2503940e2f486529164f65108c9a3a101a358ba2d0e37f16287d8d0d` | `5a9c179c112065435380c84fcd79fe83830d215e2f3f72550094777feb72fe9c` |

**Totals: 535 source Rules, 380 authoring-admitted, 155 blocked, 766 native
documents.** This output remains unverified. The public original CLI's 247
Windows admissions use strict broken-reference inventory options; a different
source-model setting in an old unit test yielded 249. No prior proof is
rebaselined here. The semantic contract pack's SHA-256 is
`b78c4db59da4cb2bad4f783e9562a5df9060de1a0e60f29ff4afceef8443ca70`.
CI regenerates this pack from the frozen flat SCAP-NG snapshot and the official
OVAL-Community v5.12.3 source pinned to
`2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`, using
byte-exact copies of the previously accepted generator helpers. It reproduces
the original pack exactly. Of the original 54 research OVAL XSDs, **52 are
byte-identical** to this official tag; two `independent-*` XSDs contain
additional historical `sqlext` declarations. Those differences do not alter
the 52-capability automatic-converter pack. The full 100-capability editor
metadata export still requires a separate audited migration. See
[generator independence audit](GENERATOR-INDEPENDENCE.md).

## Quarterly corpus policy

- **Regression lane:** Keep this Q3 2026 archive, repository revision, Git blob
  identities and SHA-256 ZIP hashes immutable. Its original converter output
  and blocker counts remain a compatibility baseline, not a statement about
  the newest content or every SCAP-NG conversion mode.
- **Current qualification lane:** When the next NIWC quarterly publication is
  released (expected Q4 2026), select and pin a *new* archive/revision and
  compare source Rule identities, check constructs, warnings and conversion
  outcomes. Do not update Q3 goldens in place or silently replace provenance.
- Both lanes distinguish complete Rule-policy preservation, draft admission,
  strict automated authoring admission, independent proof and scanner results.

## Cutover prerequisite

The source ZIP relocation and converter CI's research-repository dependency
gates are provisionally met using pinned public NIWC/OVAL checkouts,
byte-audited generator helper copies, and pre-migration original CLI goldens.
The original CLI remains available as an **optional, separate differential
test** when a local research checkout is provided; its absence does not skip
the frozen per-benchmark or CLI-byte acceptance tests. Repository renaming,
100-capability editor metadata and canonical editor pins remain separate gates.
Do not silently regenerate benchmarks or replace the ZIP bytes.
