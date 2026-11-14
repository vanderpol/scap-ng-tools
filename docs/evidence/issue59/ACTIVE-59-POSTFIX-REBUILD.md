# Issue #59: original Rule-ID full-65 rebuild after native 0.4.1 lowering

Run: [GitHub Actions 43540262069](https://github.com/vanderpol/scap-ng-tools/actions/runs/43540262069), completed 2026-11-14 01:31 UTC (2026-11-13 US Eastern). Converter SHA: `58b82cfd641063dc2116e5326e62c29325da5995`. Source library: `niwc-atlantic/scap-content-library@8c8e5dff860af6b1290ee9273a282db24278f8d5`. Canonical schema SHA: `0732b56567e7120ed6cb00908dff40716f76fac9`; aggregate `578315d1e00bd39449ed597ed3d39555384276bd36198a54ca0b1e3c17e72829`.

The workflow ran `scripts/rebuild_issue59_full65.py` against the **actual original 65 pinned source ZIPs**, checked the source repository commit, each ZIP SHA-256, source Rule XML identity (where recorded), original Rule IDs and exclusive owner-scope accounting, then compared every active Rule with the historical 0.4.0 source-ID ledger. Generated converter output is **authoring-validated only**, not SCC/RI runtime equivalent.

## Exact owner scope

| Scope | Benchmarks | Original Rule IDs |
| --- | ---: | ---: |
| Active | 59 | 7,990 |
| SQLEXT SQL intentionally excluded | 4 | 209 |
| Windows Server 2012/2012 R2 historical only | 2 | 693 |
| **Original sources reconciled** | **65** | **8,892** |

The newer raw classification of the 209 excluded SQL Rules is **not** admitted into the active 0.4.1 release. The original source ZIPs, SHA identities, and exclusion decisions are retained.

## Actual post-fix active 0.4.1 outcome

| Disposition | Historical 0.4.0 | Current 0.4.1 | Delta |
| --- | ---: | ---: | ---: |
| Converted, unverified | 6,479 | **6,330** | **−149** |
| Blocked | 108 | **257** | **+149** |
| Manual only | 1,403 | **1,403** | 0 |

Exact original Rule-ID transitions: **156 previously converted IDs are now blocked; 7 previously blocked IDs are converted**, resulting in net `-149`. The prior 0.4.1 release-candidate snapshot had 6,308 active conversions and 279 active blockers; the native function lowering plus subsequent adapter boundary work improved the new candidate by **22 net conversions**, without claiming which individual changes caused every recovery. The workflow's rebuild and diagnostic artifact upload steps **passed**. Its *intentional release nonregression gate failed*; **RELEASE HOLD** remains in force.

### Previously converted Rules now blocked: first decisive diagnostic by ID

| Failure family | Original Rule IDs |
| --- | ---: |
| Ambiguous allowed datatype from collected field | 114 |
| `split` requires an unambiguous string input | 19 |
| `unique` requires one scalar datatype | 17 |
| `substring` requires unambiguous string input | 1 |
| Unsupported native `relation` property | 5 |
| **Total** | **156** |

These are mutually exclusive *primary* blockers for the 156 exact Rule-ID regressions. The static type cases total **151**. The inactive generic function envelope no longer occurs among these primary blockers. Source-typed evidence may be dynamically typed: do not infer `string`, perform hidden casts, or accept the legacy OVAL Variable declaration as a native type override without an approved contract. The separate `count` multi-component source population boundary remains held until a lossless native language/RI design is approved.

Formerly blocked IDs now converted: `SV-215833`, `SV-220544`, `SV-215688`, `SV-220596`, `SV-218762`, `SV-218778`, and `SV-214492`. Their successful *authoring* admission is **not an independent correctness/scanner equivalence proof**.

## Provenance and reproducibility

[Download the Rule-ID diagnostic JSON artifact](https://github.com/vanderpol/scap-ng-tools/actions/runs/43540262069/artifacts/14092221745) (14-day workflow retention). It contains 163 exact Rule-ID status transitions, 257 blocked-ID primary reasons, and source Rule identity hashes.

- Uncompressed JSON size: **351,359 bytes**; SHA-256 `ddf17bc34abdcdc6b52e013acbed6dc6df800eec017d64fef949bc344f86a748`.
- Uploaded ZIP SHA-256 `5438cdd18921f7dfee93024d9f5c0d0d1031e67db1e3bff7eb235b19ed2b1ed9`.
- Script and regression tests: `scripts/rebuild_issue59_full65.py`, `tests/test_issue59_rebuild_full65.py`; CI job `Issue 59 full-65 source Rule admission (read-only)`. Commit of the script `08577aa56ca7bcaab68d67171baea23a938236e1`.
- Existing separate Tools workflows (source parity, semantic pack, offline schema and authoring safety) all PASS at exact SHA `58b82cfd`.
- No source ZIPs or authoring files are published from this diagnostic workflow. No automatic merge, publication or CI bypass is authorized.

## Remaining work

1. Resolve **151** dynamic/ambiguous type cases using explicit canonical language and RI evidence semantics, not converter-only guesses; see canonical [Issue #28](https://github.com/vanderpol/scap-ng/issues/28#issuecomment-6869325778).
2. Triage five native `relation` admissions by original source ID and current Object/Require grammar; retain exact comparison semantics.
3. Independently qualify source-value/status/Cardinality truth vectors and actual RI/SCC runtime outcomes; no scanner equivalence is established.
4. Keep PR #62 **DRAFT** and the canonical 0.4.1 release **HOLD** until the actual per-ID admission nonregression gate and consumer pins are verified.
