# Issue #59: post-intersection 0.4.1 source Rule-ID qualification

**Rebuilt from all 65 original signed-source ZIPs, not an estimated conversion score.** [Exact-head read-only GitHub Actions run #43542097232](https://github.com/vanderpol/scap-ng-tools/actions/runs/43542097232), completed 2026-11-14 01:50 UTC / 2026-11-13 US Eastern. Converter/code head `ec131ff391ae6982f4f2fd3dea5f6e647b9b91ab`.

- Source library `niwc-atlantic/scap-content-library@8c8e5dff860af6b1290ee9273a282db24278f8d5` with each ZIP SHA256 verified independently.
- Canonical one-active-0.4.1 snapshot `0732b56567e7120ed6cb00908dff40716f76fac9`, aggregate `578315d1e00bd39449ed597ed3d39555384276bd36198a54ca0b1e3c17e72829`.
- Original source scope **65 benchmarks / 8,892 Rules**. Release-active: **59 benchmarks / 7,990 Rules**. Excluded with source/hash identity retained: **4 SQLEXT SQL benchmarks / 209 Rules**, **2 historical Windows Server 2012/R2 benchmarks / 693 Rules**.

## Reconciled actual active Rule-ID dispositions

| Disposition | Historic 0.4.0 | Post-relation 0.4.1 | Delta |
| --- | ---: | ---: | ---: |
| Converted, authoring validated but runtime unverified | 6,479 | **6,335** | **−144** |
| Blocked | 108 | **252** | +144 |
| Manual only | 1,403 | **1,403** | 0 |
| Active original Rules | 7,990 | **7,990** | 0 |

Compared with the preceding exact-head 0.4.1 rebuild at `58b82cf` (6,330 converted / 257 blocked / 1,403 manual), this is **five verified Rule-ID restorations** and no newly regressed original Rule IDs. Compared with the initial 0.4.1 receipt before function lowering (6,308 / 279 / 1,403), this is **27 net additional conversions**.

Original Rule-ID transitions against old 0.4.0: **151 formerly converted now blocked**, **7 formerly blocked now converted**, net **−144**. The seven admitted recoveries remain source-semantic/runtime unproved; original source XML is unchanged. The exact reason distribution across the 151 outstanding regressions is mutually exclusive by first decisive blocker:

| Remaining first decisive blocker | Original Rule IDs |
| --- | ---: |
| Ambiguous collected-field datatype | **114** |
| `split` string-input type | **19** |
| `unique` scalar-input type | **17** |
| `substring` string-input type | **1** |
| **Total outstanding** | **151** |

The previous five `assessment.inputs.*.constraints.relation` errors are absent after the finite integer allowed-set intersection adapter. Exactly these **original Windows Server 2016 Rules** were restored: `SV-224867` (`r958388`), `SV-224868` (`r958388`), `SV-224869` (`r982201`), `SV-224870` (`r982200`), `SV-224871` (`r982188`). Original source witnesses and explicit narrowing table: [INPUT-RELATION-INTERSECTION.md](INPUT-RELATION-INTERSECTION.md). The provenance-pinned original converter visitor was not modified.

## Independent run and artifact receipts

- Actual source rebuild step: **PASS**, exact original Rule IDs and ZIP hashes checked.
- Diagnostic artifact upload: **PASS**. [Full original Rule-ID JSON artifact](https://github.com/vanderpol/scap-ng-tools/actions/runs/43542097232/artifacts/14092960432) (14-day retention).
- JSON uncompressed: **342,593 bytes**, SHA-256 `265847ede58d431452c1eddb75f2d986bcb133bec0821d44558be5c2ee9c65cc`.
- Uploaded ZIP archive SHA-256: `b720d5b3959b6910a8bbe150a5a1e85e5a30da31fecf7fea6e5341564dbd78aa`.
- The four standard PR #62 workflows at exact code commit `ec131ff`: authoring safety **PASS**, flat schema contracts **PASS**, 0.4.1 semantic pack handshake **PASS**, independent OVAL source tree **PASS**.
- Full-65 **release nonregression assertion: expected FAIL / HOLD** because 151 old converted original Rule IDs remain blocked. No tests were suppressed to manufacture a release pass.
- The audit deliberately distinguishes **schema/authoring validity** from **original OVAL truth vectors** and **RI/SCC runtime equivalence**. Neither independent evaluation nor executable scanner parity is claimed.

## Next owner-level dependency

Recovering the 151 remaining type cases requires an explicit typed collected evidence/result contract, documented in [canonical datatype inference Issue #28](https://github.com/vanderpol/scap-ng/issues/28#issuecomment-6869604337). The canonical pack allows 36 fields in 18 capability families to have multiple permitted datatypes; selecting an output datatype without evidence would be a hidden coercion. Test type-specific source cases, empty/error/unknown status, `unique` equality, `split`/`substring`, and downstream Require/selector comparisons against pinned OVAL source truth vectors and RI. Until qualification, **release HOLD** and Tools PR #62 remains **DRAFT**. The authoritative original ZIP and authored evidence are retained.
