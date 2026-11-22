# Current canonical 65-benchmark qualification

- Source: `niwc-atlantic/scap-content-library@8c8e5dff860af6b1290ee9273a282db24278f8d5`, archive SHA-256 `8a45fc045aff0aa2d0af2481dc115083158a1ccbe1199e7f2feec318f48763cb`
- Canonical: `scap-ng@c428fd0708da0cdd574dc9e499db714a1068bd75` (0.4.1), flat schema SHA-256 `1755c893712ef30334dc7ecadc88e5abf387c2d60a75211bc2445b7cefa2e7d4`
- Converter: `bc980cc`

## Results

| Disposition | Baseline | Candidate |
|---|---:|---:|
| Converted | 6479 | 6492 |
| Blocked | 108 | 95 |
| Manual-only | 1403 | 1403 |

Generic schema-first fixes recovered **13** previously blocked Rules: XCCDF `number`→OVAL `int/float`, `string`→OVAL `string/binary`, full selected-Test source-reference graph traversal, and `all_exist`→`one_or_more` consumer cardinality.

- Newly converted: **13**
- Newly blocked: **0**
- Nonregression: **PASS**
- Remaining blocker categories: 78 unsupported capability, 13 schema-semantic, 4 unsupported construct.
- Runtime and independent source equivalence: **not proved**.

Exact transitions and all remaining source Rule IDs are in the JSON receipt.

External output: `/tmp/tools-issue99-full65-c428-bc980cc.json`
External receipt SHA-256: `c2b04738df54894604d9c9af29c92cdae717774aa694bec1c2cdface6a381da7`
