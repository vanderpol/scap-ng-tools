# Current canonical 65-benchmark qualification

- Source: `niwc-atlantic/scap-content-library@8c8e5dff860af6b1290ee9273a282db24278f8d5`, archive SHA-256 `8a45fc045aff0aa2d0af2481dc115083158a1ccbe1199e7f2feec318f48763cb`
- Canonical: `scap-ng@c428fd0708da0cdd574dc9e499db714a1068bd75`, flat schema SHA-256 `1755c893712ef30334dc7ecadc88e5abf387c2d60a75211bc2445b7cefa2e7d4`
- Converter: `80e7d0e156a144602c0172dad5594dad9afb5f72`

## Results

| Disposition | Baseline | Candidate |
|---|---:|---:|
| Converted | 6479 | 6484 |
| Blocked | 108 | 103 |
| Manual-only | 1403 | 1403 |

The generic XCCDF/OVAL check-export type crosswalk (`number` → OVAL `int`/`float`, `string` → OVAL `string`/`binary`) and source-reference graph walk recover **13** previously blocked Rules. Eight formerly converted Rules remain blocked because one shared external Variable has conflicting consumer-derived cardinality; these are explicit holds, not ID-specific workarounds.

- Newly converted: **13**
- Newly blocked: **8**
- Nonregression: **FAIL/HOLD** (8 source-linked regressions remain)
- Remaining blocker categories: 78 unsupported capability, 13 schema-semantic, 12 unsupported construct.
- Runtime and independent source equivalence: **not proved**.

Exact transitions and all remaining source Rule IDs are in the JSON receipt.

External output: `/tmp/tools-issue99-full65-c428-80e7d0e.json`
External receipt SHA-256: `f9fec53d88e7c1f2bfdf1e7b22cbf33e788da57ccf02a878dd7a0887aab2afa4`
