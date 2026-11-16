# Active-scope exclusion: Windows Server 2012 / 2012 R2

> This document records the pre-function-integration scope baseline. The rebuilt
> candidate counts are in [ACTIVE-CANDIDATE-LEDGER.md](ACTIVE-CANDIDATE-LEDGER.md);
> that ledger supersedes the baseline counts below for current recovery status.

Owner decision: Windows Server 2012 and Windows Server 2012 R2 are not active
SCAP-NG modernization targets. This is a scope classification, not deletion or
conversion. The original benchmark ZIPs, source XML, IDs, provenance, and the
historical 65-benchmark ledger remain unchanged.

The machine-readable audit is [ACTIVE-SCOPE-2012-EXCLUSION.json](ACTIVE-SCOPE-2012-EXCLUSION.json).
It was calculated against the pinned source revision and schema pin recorded in
that file. OVAL AccessToken dependencies were resolved through direct criteria
and `extend_definition` chains; this avoids counting a definition merely because
it is in an OVAL component.

## Recalculated scope

| Scope | Benchmarks | Rules | Automated converted, unproved | Manual-only | Genuinely blocked | Intentionally excluded |
|---|---:|---:|---:|---:|---:|---:|
| Historical (retained) | 65 | 8,892 | 6,792 | 1,581 | 310 | 209 |
| Active modernization target | 63 | 8,199 | 6,391 | 1,403 | 196 | 209 |
| Excluded 2012/2012 R2 | 2 | 693 | 401 | 178 | 114 | 0 |

The two excluded benchmarks are:

- `U_MS_Windows_2012_and_2012_R2_DC_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` — 364 Rules.
- `U_MS_Windows_2012_and_2012_R2_MS_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` — 329 Rules.

The 209 SQLEXT Rules remain intentionally excluded in both views; the 2012
scope decision does not reclassify them.

## AccessToken reconciliation

The historical ledger's primary-blocker statistic is **125 AccessToken Rules**.
The source dependency audit identifies **61 of those primary blockers** in the
two excluded benchmarks (31 DC and 30 member-server Rules). Therefore **61
AccessToken primary blockers disappear from the active target**, leaving **64
primary AccessToken blockers** on supported platforms.

The source inventory separately reports 127 AccessToken Rules because it counts
all source usage, including two Rules that are not represented in the historical
primary-blocker total. Of those source Rules, 61 are excluded and **66 source
AccessToken Rules remain** on supported platforms. This distinction preserves
both existing ledger statistics and source-backed reconciliation; it is not a
claim that any AccessToken check has a native equivalent.

The remaining supported-platform AccessToken Rules are in Windows 10 and
Windows Server 2016. AccessToken remains intentionally unsupported: no
`user_right` equivalent is fabricated, and no historical result is changed.
