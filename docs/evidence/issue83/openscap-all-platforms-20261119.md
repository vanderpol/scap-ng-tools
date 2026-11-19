# Complete OVAL Self-Assertion source execution inventory — exploratory OpenSCAP

This receipt records all 144 XML files in the pinned OVAL Self-Assertion corpus through OpenSCAP 1.3.9 on the current unprivileged Ubuntu host. It is **not** SCAP-NG/OVAL 5.12.3 equivalence: OpenSCAP reports OVAL 5.11.1 and `--skip-valid` was required because its installed schemas do not include pinned OVAL 5.12.3.

## Aggregate results

- Source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`
- XML files: **144** across 12 source families
- Authored Tests in those XML files: **785**
- Observed Test results: **770**; unexecuted XML Tests: **15**
- Additional full-corpus Tests in `agnostic/oval-def-ext.zip`: **18**, not included in this XML-only run
- Completed OpenSCAP runs: **141**; engine execution errors: **3**
- Definition outcomes: **TRUE 62, FALSE 22, UNKNOWN 76, ERROR 4**
- Observed Test outcomes: **TRUE 274, FALSE 173, UNKNOWN 302, ERROR 21**

| Family | XML | Source Tests | Observed | Unexecuted | Def T/F/U/E | Test T/F/U/E |
|---|---:|---:|---:|---:|---|---|
| agnostic | 35 | 310 | 306 | 4 | 40/3/1/1 | 180/115/1/10 |
| aix | 2 | 2 | 2 | 0 | 0/0/2/0 | 0/0/2/0 |
| asa | 2 | 2 | 2 | 0 | 0/0/2/0 | 0/0/2/0 |
| ios | 11 | 16 | 16 | 0 | 7/0/4/0 | 7/0/9/0 |
| iosxe | 11 | 17 | 17 | 0 | 7/0/4/0 | 7/0/10/0 |
| junos | 2 | 2 | 2 | 0 | 0/0/2/0 | 0/0/2/0 |
| linux | 16 | 62 | 52 | 10 | 1/7/4/2 | 19/19/10/4 |
| macos | 20 | 43 | 43 | 0 | 0/3/17/0 | 2/8/30/3 |
| panos | 2 | 2 | 2 | 0 | 0/0/2/0 | 0/0/2/0 |
| solaris | 6 | 21 | 21 | 0 | 0/2/4/0 | 2/3/15/1 |
| unix | 12 | 72 | 71 | 1 | 7/3/2/1 | 55/6/8/2 |
| windows | 25 | 236 | 236 | 0 | 0/4/32/0 | 2/22/211/1 |
| **Total** | **144** | **785** | **770** | **15** | **62/22/76/4** | **274/173/302/21** |

The JSON preserves every authored XML Test ID, every observed source Test ID/result, every Definition ID/result, source/result hashes, timing, status and sanitized diagnostic. Unexecuted IDs are explicit rather than silently treated as UNKNOWN or success.

## Unexecuted Tests and root causes

- `agnostic/oval-def_merge.xml`: `tst:1`–`:tst:4`; OpenSCAP aborts on the known malformed merge Variable component.
- `linux/linux-def_selinuxboolean_test.xml`: 3 Tests; SELinux probe engine execution error in the restricted Ubuntu environment.
- `linux/linux-def_selinuxsecuritycontext_test.xml`: 7 Tests; SELinux probe engine execution error in the restricted Ubuntu environment.
- `unix/unix-def_sshd_test.xml`: `tst:483`; OpenSCAP source baseline has the criterion commented out, matching the source correction tracked by PR #17.
- The 18 Tests inside `agnostic/oval-def-ext.zip` require a separate archive-member staging step and are not silently counted as executed by this harness.

Other Linux errors include unprivileged `/proc`/sysctl acquisition and missing RPM database effects. Windows, macOS, Solaris, iOS, iOSXE, ASA, AIX, Junos and PAN-OS outcomes are wrong-platform diagnostics on Ubuntu, not platform qualification.

## Reproduction

```bash
SRCROOT=$(mktemp -d /tmp/issue83-openscap-source.XXXXXX)
OUTBASE=$(mktemp -d /tmp/issue83-openscap-run.XXXXXX)
git -C /tmp/SCAP-Self-Assertion-pr19-stack archive \
  e3538595c5083b9c34d937a81d319234df9bbfaa SCAP_1.4/OVAL_Test_Content \
  | tar -x -C "$SRCROOT"
python3 scripts/qualify_openscap_oval.py \
  --corpus "$SRCROOT/SCAP_1.4/OVAL_Test_Content" \
  --source-commit e3538595c5083b9c34d937a81d319234df9bbfaa \
  --output "$OUTBASE/results" --timeout-seconds 30 \
  --max-result-bytes 67108864
```

The harness refuses overwrite, uses no shell interpolation, enforces per-file limits, inventories authored Tests, extracts Definition/Test outcomes without retaining Item values, and sanitizes host paths/identifiers in the committed ledger. This execution used the unprivileged Ubuntu environment and no sudo.
