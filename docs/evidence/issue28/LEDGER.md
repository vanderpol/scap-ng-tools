# Issue #28 complete conversion ledger

`BLOCKER-AUDIT.json` is the retained baseline ledger. Rebuild the current
mutually-exclusive ledger from the original signed source archives with:

```sh
PYTHONPATH=src python scripts/build_issue28_ledger.py \
  --source-dir /path/to/65-pinned-zips \
  --schema-root /path/to/scap-ng \
  --output docs/evidence/issue28/COMPLETE-LEDGER.json
```

The output preserves every source ZIP hash, Rule ID, source Rule hash, check
selection, and blocker. Each Rule is assigned exactly one category:

- automated converted and independently proved;
- automated converted but unproved;
- manual-only;
- genuinely blocked; or
- intentionally excluded.

SQLEXT-dependent SQL benchmark archives are excluded by default. Use
`--include-sqlext` only for a diagnostic run; it must not be published as the
in-scope conversion result. Access-token capabilities remain blockers and are
never replaced with fabricated native selectors.

The current repository does not publish a regenerated 65-archive result. A
run with the pinned original content is required before reporting benchmark
counts as current. The historical 8,892-Rule baseline remains the reconciliation
sum, including explicit exclusions.
