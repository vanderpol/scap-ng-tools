# Complete OVAL Self-Assertion source execution inventory — exploratory OpenSCAP

This is the first complete 144-XML source execution inventory from the pinned OVAL Self-Assertion corpus. It runs each source XML file through OpenSCAP 1.3.9 on the current unprivileged Ubuntu host. It is **not** SCAP-NG/OVAL 5.12.3 equivalence: OpenSCAP reports OVAL 5.11.1 and `--skip-valid` was required because its installed schemas do not include pinned OVAL 5.12.3.

## Aggregate results

- Source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`
- XML files: **144** across 12 source families
- Completed OpenSCAP runs: **141**
- Engine execution errors: **3**
- Definition outcomes: **TRUE 62, FALSE 22, UNKNOWN 76, ERROR 4**

| Family | XML files | Completed | Engine errors | TRUE | FALSE | UNKNOWN | ERROR |
|---|---:|---:|---:|---:|---:|---:|---:|
| agnostic | 35 | 34 | 1 | 40 | 3 | 1 | 1 |
| aix | 2 | 2 | 0 | 0 | 0 | 2 | 0 |
| asa | 2 | 2 | 0 | 0 | 0 | 2 | 0 |
| ios | 11 | 11 | 0 | 7 | 0 | 4 | 0 |
| iosxe | 11 | 11 | 0 | 7 | 0 | 4 | 0 |
| junos | 2 | 2 | 0 | 0 | 0 | 2 | 0 |
| linux | 16 | 14 | 2 | 1 | 7 | 4 | 2 |
| macos | 20 | 20 | 0 | 0 | 3 | 17 | 0 |
| panos | 2 | 2 | 0 | 0 | 0 | 2 | 0 |
| solaris | 6 | 6 | 0 | 0 | 2 | 4 | 0 |
| unix | 12 | 12 | 0 | 7 | 3 | 2 | 1 |
| windows | 25 | 25 | 0 | 0 | 4 | 32 | 0 |
| **Total** | **144** | **141** | **3** | **62** | **22** | **76** | **4** |

Counts are Definition outcomes extracted from OpenSCAP results, not source expected outcomes and not RI results. A file can contain more than one Definition.

## Root-cause observations

- Agnostic merge execution hit OpenSCAP's NULL component assertion for the known malformed merge Variable source; this is consistent with the open source correction PR #7 and is not a SCAP-NG result.
- Linux SELinux boolean/security-context probes produced two engine execution errors in the restricted Ubuntu environment.
- Other Linux errors include unprivileged `/proc`/sysctl acquisition and missing RPM database effects; these remain host-authority diagnostics.
- Windows, macOS, Solaris, iOS, iOSXE, ASA, AIX, Junos and PAN-OS outcomes are wrong-platform diagnostics on Ubuntu, not platform qualification.

The JSON ledger preserves every source path/hash, Definition ID/result, duration, output size/hash, bounded status and sanitized diagnostic. The CSV contains the per-file summary. Raw result XML/logs remain external under the recorded output root and are not committed.

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

The harness refuses overwrite, uses no shell interpolation, enforces per-file limits and sanitizes host paths/identifiers in the committed ledger. This execution used the unprivileged Ubuntu environment and no sudo.
