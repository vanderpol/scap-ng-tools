# Issue #28 applicability coverage audit

Pins: source `8c8e5dff860af6b1290ee9273a282db24278f8d5`, schema `919732d4c570b521edf82196a7694dfd8c27fe50`, schema SHA-256 `6bf2fa369fd7b9a0153899ac25109af3e3f9aa59c0f4aa6bb3be1aebd5b14fa0`.

## Finding

**Classification: intentional conversion-pipeline limitation.** The canonical schema supports the required references; the source contains resolvable CPE/OVAL platform data; the converter deliberately emits a fixture catalog instead.

| Measure | Count | Coverage |
|---|---:|---:|
| Source benchmarks | 63 | — |
| Source Rules | 8199 | — |
| Rules with inherited platform refs | 8199 | 100.0% |
| Effective XCCDF platform refs | 11184 | — |
| CPE platform-specification definitions | 185 | across 32 benchmarks |
| CPE/OVAL platform fact refs | 185 | — |
| Fact refs resolved by source graph | 185 | 100.0% |
| Fact closures using supported capabilities | 183 | 98.919% |
| Fact closures requiring SQLEXT | 2 | — |
| Native applicability catalogs present | 59 | — |
| Native catalogs with conditions | 0 | 0.0% |
| Native Rule files with applicability | 0 / 7882 | 0% |

## Source-to-native status by Rule class

| Candidate class | Rules | Effective platform refs |
|---|---:|---:|
| Automated converted | 6479 | 9130 |
| Manual-only | 1403 | 1693 |
| Blocked | 108 | 150 |
| Intentionally excluded | 209 | 211 |

The released archive is unchanged. Empty catalogs are an explicit limitation, not proof that source applicability is absent.

## Smallest corrective implementation

- Add a source applicability graph extractor for inherited XCCDF platform refs, CPE URIs, and CPE platform-specification logical-test/fact-ref nodes.
- Reuse the existing OVAL-to-native Assessment conversion for each unique supported platform fact closure in the 183 supported active fact closures, emitting shared applicability Assessments rather than duplicating Tests.
- Emit applicability catalog condition keys and references, then attach inherited platform condition references to native Rules/Benchmark using the existing 0.4 shared Assessment mechanism.
- Keep the 58 CPE URI identities and 92 custom platform identities as provenance until a native executable identity contract exists; never turn them into fabricated checks.
- Keep SQLEXT fact closures explicitly blocked/excluded; do not infer or fabricate platform semantics.
- Add source identity, resolution, and no-runtime-equivalence receipts before changing publication output.
