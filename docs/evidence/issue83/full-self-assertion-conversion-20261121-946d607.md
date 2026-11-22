# Full Self-Assertion conversion receipt (946d607)

- Source: `OVAL-Community/SCAP-Self-Assertion@d91e6ba33841e3202dc27d3e0d469a7abd939b16`
- OVAL schema: `OVAL-Community/OVAL@2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`
- Canonical: `vanderpol/scap-ng@c428fd0708da0cdd574dc9e499db714a1068bd75` (0.4.1)
- Converter: `946d607d1e1ff328c1e0883822c664428aae4aae`

## Complete source ledger

- Definitions: **167** total; **166** source-valid converted; **1** source-invalid; **0** blocked.
- Tests: **799** total; **769** source-valid converted; **30** source-invalid; **0** blocked.
- Schema-valid source-invalid artifacts retained separately: **1**.

The sole source-invalid Definition is `oval:org.mitre.oval.test:def:580` in `agnostic/oval-def_time_difference_function.xml` (SHA-256 `6cd0a42d7b3c05a7212d410f18f7aba30d0f95f1c167996e033b10298af6a68c`), with 30 Tests and 27 Variable declaration/result mismatches. OVAL `time_difference` returns `int`; these source declarations say `string`. This is not silently normalized or counted as lossless conversion.

## Proof boundaries

Structural JSON/YAML validation passed. Runtime execution and independent OVAL equivalence were **not run**. No expected outcomes or fixture values entered conversion.

- External evidence: `/tmp/tools-issue99-full-d91-946d607`
- Manifest SHA-256: `ffd2b550d3ffe0142173511eee1d4bddbc046625e7971d1fb2299bd0198f66be`
- Manifest artifact entries: `680`
