# Linux/UNIX Self-Assertion exploratory source execution — 2026-11-19

This receipt records an independent run of the pinned original OVAL source through OpenSCAP 1.3.9 on the current Ubuntu host. It is **not** SCAP-NG/OVAL 5.12.3 equivalence: OpenSCAP reports OVAL 5.11.1, and `--skip-valid` was required because it does not contain the pinned 5.12.3 schema family.

## Scope and result

- Source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`
- Families: Linux and UNIX
- XML files: **28** (Linux 16, UNIX 12)
- Completed engine runs: **26**; execution errors: **2**
- Definition outcomes: **TRUE 8, FALSE 10, UNKNOWN 6, ERROR 3**
- Per-family outcomes:
  - Linux: TRUE 1, FALSE 7, UNKNOWN 4, ERROR 2; 14 completed, 2 engine execution errors
  - UNIX: TRUE 7, FALSE 3, UNKNOWN 2, ERROR 1; all 12 completed

The machine-readable JSON preserves every source file SHA-256, Definition ID/result, result SHA-256, duration, bounded result bytes, status and sanitized diagnostic. CSV contains the same per-file summary columns. Raw OpenSCAP result XML/logs remain external under the recorded `/tmp` output root.

## Observed holds

- Linux environment-variable acquisition produced unprivileged `/proc` permission diagnostics and an ERROR Definition result.
- Linux SELinux boolean/security-context probes produced engine execution errors; these are acquisition/engine observations, not converted RI outcomes.
- Linux sysctl included permission-denied observations and an ERROR result.
- RPM tests observed no usable RPM database on this Ubuntu host and returned FALSE; this is diagnostic, not RHEL qualification.
- UNIX SSHD returned UNKNOWN; UNIX file, password, process and other tests produced both TRUE/FALSE/UNKNOWN outcomes.

No source-authored expected outcomes were passed into OpenSCAP, and no result was promoted to RI equivalence. Wrong-platform and unprivileged observations remain explicit.

## Reproduction

The reusable bounded harness is [`scripts/qualify_openscap_oval.py`](../../../scripts/qualify_openscap_oval.py):

```bash
SRCROOT=$(mktemp -d /tmp/issue83-openscap-source.XXXXXX)
OUTBASE=$(mktemp -d /tmp/issue83-openscap-run.XXXXXX)
git -C /tmp/SCAP-Self-Assertion-pr19-stack archive \
  e3538595c5083b9c34d937a81d319234df9bbfaa SCAP_1.4/OVAL_Test_Content \
  | tar -x -C "$SRCROOT"
python3 scripts/qualify_openscap_oval.py \
  --corpus "$SRCROOT/SCAP_1.4/OVAL_Test_Content" \
  --family linux --family unix \
  --source-commit e3538595c5083b9c34d937a81d319234df9bbfaa \
  --output "$OUTBASE/results" --timeout-seconds 60 \
  --max-result-bytes 67108864
```

The harness refuses overwrite, enforces per-file timeout/result limits, uses no shell interpolation, and sanitizes host paths/identifiers in the committed ledger.
