# Applicability qualification matrix

| Evidence | Source kind | Result |
|---|---|---|
| Windows 11 R700 | Real SCAP 1.4 | Converted, but missing Group-local/nested levels |
| Pinned 65 corpus | Real corpus audit | 65/65 scanned; 0 Group-local declarations |
| `qualification-levels.xccdf.xml` | Standalone standards-conformant fixture | Benchmark → Group → nested Group → Rule converted; RI probes pass |

The standalone fixture is synthetic regression evidence, not source provenance.
Direct CPE URI mappings remain ERROR holds. Profile-disabled remains
`not_evaluated`, distinct from FALSE/`not_applicable`. See the JSON matrix and
individual receipts for exact SHA-256 pins.

## Release blockers

1. Real source coverage for Group-local/nested platform inheritance is absent
from the pinned corpus; the standalone fixture does not replace it.
2. Qualified executable CPE mappings are not established.
3. Hosted RI qualification remains blocked by runner billing/startup failure.
