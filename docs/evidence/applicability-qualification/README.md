# Applicability qualification receipt

This is a bounded, reproducible qualification harness, not corpus output.
Run from this repository with the exact public OpenSCAP source URL pinned in
`scripts/qualify_applicability.py`:

```sh
PYTHONPATH=src python scripts/qualify_applicability.py \
  --output /tmp/applicability-qualification
(cd ../scap-ng-ri && go run ./cmd/ri-applicability-qualification \
  --input /tmp/applicability-qualification/ri-input.json \
  --output /tmp/applicability-qualification/ri-results.json)
PYTHONPATH=src python scripts/qualify_applicability.py \
  --output /tmp/applicability-qualification-final \
  --ri-results /tmp/applicability-qualification/ri-results.json
```

The receipt records the immutable upstream source SHA and the exact merged converter implementation commit. The original PR head `654d6481d6d86f47e9b648bc31b992990ad67213` was merged with the moving Issue 59 base for CI qualification.

The receipt records the immutable upstream source SHA and a separate SHA for
the deterministic hierarchy overlay. The overlay is necessary because the
public OpenSCAP regression source has Benchmark/Group/Rule platforms but no
nested Group; it is explicitly not claimed as upstream source provenance.
Direct CPE URI conditions remain unqualified holds. The RI probe table proves
TRUE, FALSE/not_applicable, UNKNOWN, ERROR, and profile-disabled/not_evaluated
wire distinctions, but does not claim CPE scanner equivalence.

## Real SCAP 1.4 gate

`real-source-audit.json` audits and converts the pinned Windows 11 R700 SCAP
1.4 archive. It is the authoritative gate receipt for real content. The source
has Benchmark and Rule-local platforms, but **zero Group-local platforms and
zero nested Groups**, so the requested all-level real-source qualification is
blocked. The converter still ran with the pinned 0.4.1 schema and produced a
deterministic native-document digest; the missing source levels are not filled
by the converter. The separate OpenSCAP overlay harness is retained only as a
converter regression probe and is explicitly not a real-source qualification.
