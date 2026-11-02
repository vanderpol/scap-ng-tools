# Pinned SCAP 1.4 benchmark inventory fixture ledger

These are **source-frozen compatibility inputs**, not a claim that upstream
vendor content is the latest publication, that all findings can be converted,
or that any target host has been scanned. The corpus was originally pinned from
`niwc-atlantic/scap-content-library` revision
`8c8e5dff860af6b1290ee9273a282db24278f8d5` and is referenced through
`vanderpol/scap-ng` research commit
`d12a644f4607cdc9c9ada50e3a96d4fd0060c6d9`.

Each fixture is retrieved into a **separate temporary CI checkout**. It is
neither embedded in the tools wheel nor distributed under this repository's
Apache-2.0 license. CI verifies the exact source ZIP SHA-256 before reading it.

| Fixture / suite | ZIP SHA-256 | Original Rule count |
| --- | --- | ---: |
| `server2025-signed.zip` / `v04-direct-prototype` | `2f46264b5fa21c8a033236121794ebe372314bf7458dac0aca4f81179fe7ece0` | 291 |
| `U_Active_Directory_Domain_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip` / `v04-draft-compatibility` | `94740b7929dd868043ab1b476c3b568712fc26d045a4d450359cea90effbfa1c` | 36 |
| `U_Amazon_Linux_2023_V1R2_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` / `v04-draft-compatibility` | `88cc35f98c9ff96c567110c284c06e6adfc556fd59967019bdec6fd1cc5a204f` | 187 |
| `U_MS_Windows_Defender_Firewall_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV14-signed.zip` / `v04-draft-compatibility` | `d16c868152e14bab0a1e2ecdfa6ec889972e068625d4d20d4ac3f861ff2009ca` | 21 |

**Total: 535 unique Rule entries across four benchmark inventories.**

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

## Cutover prerequisite

Before renaming the original `scap-ng` repo to private `scap-ng-research`,
review redistribution rights and relocate these fixtures (or a legally suitable
reproducible public-source acquisition recipe) to a stable, version-pinned
source available to the canonical specification and tools CI. Update the
checkout reference by reviewed PR; never silently regenerate benchmarks or
replace the source ZIP bytes while claiming the same baseline.
