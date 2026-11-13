# Issue #60 Firefox Linux aggregation recovery

Pinned signed source:
`U_MOZ_Firefox_Linux_V6R7_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip`
SHA-256:
`c8afb0321ec0db0c831ddbc617ae734b2af3369d914d5034a4595e1d4be9f3b7`.

The shared OVAL visitor now lowers multi-component aggregations directly:

- `unique`: one expression or an ordered non-empty expression list;
- `concat`: ordered component list, retaining source Cartesian-product semantics;
- `merge.values`: one expression or an ordered non-empty expression list;
- no generic `function` envelope and no Firefox-specific special case.

## Pinned Firefox result

| source Rules | OVAL automated | converted drafts | manual-only |
|---:|---:|---:|---:|
| 33 | 30 | 30 `CONVERTED_UNVERIFIED` | 3 |

Manual-only Rules remain **SV-251545, SV-251550, and SV-251560**. The 30
automated outputs retain the shared source Variable graph and use the native
ordered `unique` list containing the `/etc/firefox/policies` literal and the
nested `concat` candidate path.

The candidate expression schema from canonical commit
`9214368a046bc103e74488b8e3cadb9a0cbf9ffc` validates all 30 emitted Variable
expressions. This is authoring validation only: scanner execution and
independent source/runtime equivalence remain `not_run`/`not_proved`.

Machine-readable source IDs, selectors, hashes, and statuses are in
`issue60-firefox-linux.json`.

A pinned inventory scan of the same 65 signed source ZIPs reconciles **65
benchmarks / 8,892 Rules** and finds exactly one multi-component aggregation
graph: the Firefox Linux `policies.json` Variable above. No other benchmark
source graph uses this construct. A complete converter-wide 65-rule admission
run remains a separate gate requiring the exact 0.4.1 schema pack.
