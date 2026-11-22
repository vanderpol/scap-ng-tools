# Full OVAL Self-Assertion conversion — 2026-11-21

Production Tools conversion against the exact corrected source `OVAL-Community/SCAP-Self-Assertion@d91e6ba33841e3202dc27d3e0d469a7abd939b16` and canonical SCAP-NG 0.4.1 `c428fd0708da0cdd574dc9e499db714a1068bd75` completed without conversion blockers.

| Measure | Result |
|---|---:|
| Definitions | 167 / 167 converted |
| Tests | 799 / 799 converted |
| Blocked Definitions | 0 |
| Blocked Tests | 0 |
| Schema-valid YAML documents | 167 |
| Runtime execution | Not run |
| Independent OVAL equivalence | Not proved |

The run used only the production CLI and unchanged source XML. It did not inject expected outcomes, companion fixture values, or collected Items. Every generated artifact is retained externally at `/tmp/tools-issue99-full-d91-c30f4af` with a manifest SHA-256 receipt; no generated corpus is committed.

`def:562` is included with all 18 source-linked Tests and is `CONVERTED_UNVERIFIED`. The prior canonical external-Input hold is therefore recovered structurally. Native Input binding and RI execution with explicit values remain separate runtime work.

Machine receipt: [`full-self-assertion-conversion-20261121-c30f4af.json`](full-self-assertion-conversion-20261121-c30f4af.json).
