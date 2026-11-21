# Exploratory OpenSCAP source execution — Self-Assertion PRs #6 and #16

This is an independent **source-engine execution receipt**, not authoritative SCAP-NG equivalence. OpenSCAP 1.3.9 reports OVAL 5.11.1 and does not contain the pinned OVAL 5.12.3 schemas, so validation was explicitly skipped.

## Results

| Source correction | Definition | Base | Corrected | Interpretation |
|---|---|---:|---:|---|
| PR #6 PID Variable datatype | `oval:navy.navwar.niwcatlantic.scc.test:def:1` | false | false | Ubuntu/macOS mismatch and `/proc` acquisition diagnostics; not a datatype proof |
| PR #16 deprecated upward recursion removal | `oval:org.mitre.oval.test:def:48` | false | false | Ubuntu fixture/target mismatch; not a recursion equivalence proof |

PR #6 generated 208/209 acquisition-error lines in the base/corrected logs, primarily unprivileged `/proc/*/environ` access. PR #16 generated no acquisition-error lines. Exact source commits, result hashes, and sanitized diagnostics are in the machine-readable receipt.

## Required interpretation

- These are source-side exploratory outcomes only.
- No source expected result was injected.
- Running macOS content on Ubuntu is not macOS qualification.
- `--skip-valid` is required only because OpenSCAP 1.3.9 lacks the pinned 5.12.3 schema; it must not be treated as schema validation.
- No RI/OpenSCAP equivalence claim is made.

Raw result XML and logs remain outside Git under bounded `/tmp` directories. Reproduction commands and exact source retrieval are recorded in the JSON receipt.
