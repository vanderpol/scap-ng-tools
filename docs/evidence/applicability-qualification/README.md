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

The receipt records the immutable upstream source SHA and a separate SHA for
the deterministic hierarchy overlay. The overlay is necessary because the
public OpenSCAP regression source has Benchmark/Group/Rule platforms but no
nested Group; it is explicitly not claimed as upstream source provenance.
Direct CPE URI conditions remain unqualified holds. The RI probe table proves
TRUE, FALSE/not_applicable, UNKNOWN, ERROR, and profile-disabled/not_evaluated
wire distinctions, but does not claim CPE scanner equivalence.
