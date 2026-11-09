# Issue #28 preservation recovery test receipt

**Status: preservation-only; unqualified.** These tests verify that the copied
recovery files retain their expected source/provenance fingerprints. They do
not prove OVAL equivalence, compiler execution, scanner behavior, or full-65
conversion.

Command:

```sh
PYTHONPATH=src python -m unittest \
  tests.test_converter_provenance \
  tests.test_issue28_manual_recovery -v
```

Result on the recovery worktree:

- 5 tests run
- 3 passed
- 2 expected skips because source ZIPs and the accepted schema snapshot were intentionally not copied into the PR
- 0 failures

The two skipped manual-selection tests remain source-backed tests in the
preserved tree; the 65 source ZIPs remain at the VM-local path recorded in
`RECOVERY-PRESERVATION-MANIFEST.json` and are not committed.
