# Complete OVAL Self-Assertion source execution inventory — exploratory OpenSCAP

This receipt records all 144 XML files plus the external-variable OVAL XML member in the pinned Self-Assertion corpus through OpenSCAP 1.3.9 on the current unprivileged Ubuntu host. It is **not** SCAP-NG/OVAL 5.12.3 equivalence: OpenSCAP reports OVAL 5.11.1 and `--skip-valid` was required because its installed schemas do not include pinned OVAL 5.12.3.

## Aggregate results

- Source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`
- Source files: **145** execution units (144 XML files + `agnostic/oval-def-ext.zip!oval-def-ext.xml`)
- Authored Tests: **803** (785 XML Tests + 18 archive-member Tests)
- Observed Test results: **788**; unexecuted: **15**
- Completed OpenSCAP runs: **142**; engine execution errors: **3**
- Definition outcomes: **TRUE 63, FALSE 22, UNKNOWN 76, ERROR 4**
- Observed Test outcomes: **TRUE 292, FALSE 173, UNKNOWN 302, ERROR 21**

| Family | Units | Source Tests | Observed | Unexecuted | Def T/F/U/E | Test T/F/U/E |
|---|---:|---:|---:|---:|---|---|
| agnostic (XML + archive member) | 36 | 328 | 324 | 4 | 41/3/1/1 | 198/115/1/10 |
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
| **Total** | **145** | **803** | **788** | **15** | **63/22/76/4** | **292/173/302/21** |

The JSON preserves every authored Test ID, every observed source Test ID/result, every Definition ID/result, source/archive/member hashes, timing, status and sanitized diagnostic. Unexecuted IDs are explicit rather than silently treated as UNKNOWN or success.

## Unexecuted Tests and root causes

- `agnostic/oval-def_merge.xml`: `tst:1`–`:tst:4`; OpenSCAP aborts on the known malformed merge Variable component.
- `linux/linux-def_selinuxboolean_test.xml`: 3 Tests; SELinux probe engine execution error in the restricted Ubuntu environment.
- `linux/linux-def_selinuxsecuritycontext_test.xml`: 7 Tests; SELinux probe engine execution error in the restricted Ubuntu environment.
- `unix/unix-def_sshd_test.xml`: `tst:483`; OpenSCAP source baseline has the criterion commented out, matching source correction PR #17.

The archive member was executed with its authored external-variable file. It returned TRUE for all 18 Tests in the legacy engine; this is source execution evidence only and does not resolve the canonical external-Variable/Input conversion hold. Other Linux errors include unprivileged `/proc`/sysctl acquisition and missing RPM database effects. Windows, macOS, Solaris, iOS, iOSXE, ASA, AIX, Junos and PAN-OS outcomes are wrong-platform diagnostics on Ubuntu, not platform qualification.

## Reproduction

```bash
SRCROOT=$(mktemp -d /tmp/issue83-openscap-source.XXXXXX)
OUTBASE=$(mktemp -d /tmp/issue83-openscap-run.XXXXXX)
git -C /tmp/SCAP-Self-Assertion-pr19-stack archive \
  e3538595c5083b9c34d937a81d319234df9bbfaa SCAP_1.4/OVAL_Test_Content \
  | tar -x -C "$SRCROOT"
python3 scripts/qualify_openscap_oval.py \
  --corpus "$SRCROOT/SCAP_1.4/OVAL_Test_Content" \
  --archive "$SRCROOT/SCAP_1.4/OVAL_Test_Content/agnostic/oval-def-ext.zip" \
  --source-commit e3538595c5083b9c34d937a81d319234df9bbfaa \
  --output "$OUTBASE/results" --timeout-seconds 30 \
  --max-result-bytes 67108864
```

The harness refuses overwrite, uses no shell interpolation, enforces per-file limits, inventories authored Tests, extracts Definition/Test outcomes without retaining Item values, supports archive-member Variables, and sanitizes host paths/identifiers in the committed ledger. This execution used the unprivileged Ubuntu environment and no sudo.
