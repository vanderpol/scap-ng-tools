# Pinned SCAP 1.4 benchmark inventory fixture ledger

These are **source-frozen compatibility inputs**, not a claim that upstream
vendor content is the latest publication, that all findings can be converted,
or that any target host has been scanned. The corpus was originally pinned from
`niwc-atlantic/scap-content-library` revision
`8c8e5dff860af6b1290ee9273a282db24278f8d5` and is referenced through
`vanderpol/scap-ng-research` (now private) research commit
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
| Windows Server 2025 | `b8e006eceeaca1d1e669e88d2f9336ea3ad165323409a2ff49f80e0641e9b238` | `0558217d6c90a39bf7f0e9b9bf8f8235f391df4152be639968ac1d3e132f41ff` |
| Active Directory Domain | `9335f772f3cc5a1952c46d66b1087f17dbd2105ce975b4f9156f29fc96d8d719` | `a904fa7e88ff40bdea90825aac5d8b102a28fbd89d24b7c43b78aebe3b790824` |
| Amazon Linux 2023 | `6b3cdccfda5097f549f7372ae95c661f88b03d2097e9ebce366c4d99e31d0823` | `af1acfc9a2a7454153f629e2e1a88823f794bfa99e5cc4b4aef2cba980c7f4e1` |
| Windows Defender Firewall | `f0ba480d3e3d2c61600e68cc1e34daecfc8fe90804912bde5b4484f4440921b4` | `fde316371acb5b11e9f5b747b3138ec66e5ea07dc8609e6480543d2f0a7210bc` |

The separate focused conversion baseline remains six native documents from
the two selected Windows Server 2025 Rules, with canonical native SHA-256
`497ac2042ddefd126c9723f181d655b1d5d4c4fad441c3f986a4b77315584c69`.
Inventory is read-only and does not establish authoring admission or proof.

## Pinned automatic authoring-conversion admission

The hashes in the table below are the current owner-amended 0.4 output hashes
used by the portable Tools qualification and tests. Earlier pre-amendment
native/trace hashes remain historical evidence and are not silently rebaselined.

These are the original public `--all-rules` CLI outputs, independently computed
from the same four signed source ZIPs with the original 0.4 semantic validators.
Both the installed converter and the source oracle must match all three hashes.
Hash construction is the same canonical sorted JSON serialization as above.

| Source | Admitted / blocked | Native docs SHA-256 | Automatic coverage SHA-256 | Automatic source trace SHA-256 |
| --- | --- | --- | --- | --- |
| Windows Server 2025 | 247 / 44 | `5687a4919b66e4e38e9d9dc2f59131393cf9683b0af768caf0ca4c3fa72deca8` | `233fa961e84f101107cb62c5b810aa4719309c8bb5c31bbe2e212a09676c5bf4` | `28ccb0600d666f99b76b36164776a7b442276ef8282f614d87b28c470dcf95d4` |
| Active Directory Domain | 15 / 21 | `69d6606cf3b8c1e5ae943b5282ecf35a258556e5ce305b5ac1f4f9e1aa3bb10b` | `f90aacf66975f5d3cadf4d1d941142ad2a40f8c6a4c682eab491e15b2e604a53` | `450aadbc110a26934a5688aefbed0c86e0e967ead6e1041cbc376e858f7dee64` |
| Amazon Linux 2023 | 118 / 69 | `7a9a7b578bf6f7f3498e58369f64340c719f7b50e5a376058974aefa20f6db4d` | `da41d34d4c1b307097cb55c93e700e4bfa3f85950485c189d6f2f22a9f67a375` | `09d77b842843d3cab5b3dd4e9e28af253799ac3878608cd65239dc47a8d880e2` |
| Windows Defender Firewall | 0 / 21 | `44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a` | `5e70d08b2503940e2f486529164f65108c9a3a101a358ba2d0e37f16287d8d0d` | `fde316371acb5b11e9f5b747b3138ec66e5ea07dc8609e6480543d2f0a7210bc` |

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
the 52-capability automatic-converter pack. The separate
[editor metadata export audit](EDITOR-PACK-CUTOVER.md) reproduces every one
of the original 235 resources across 100 capabilities, while excluding
`sqlext` targeting equivalence by owner direction. See also the
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
