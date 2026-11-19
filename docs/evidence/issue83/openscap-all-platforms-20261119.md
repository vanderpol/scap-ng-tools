# Complete OVAL Self-Assertion source execution inventory — exploratory OpenSCAP

This receipt records all 144 XML files in the pinned OVAL Self-Assertion corpus through OpenSCAP 1.3.9 on the current unprivileged Ubuntu host. It is **not** SCAP-NG/OVAL 5.12.3 equivalence: OpenSCAP reports OVAL 5.11.1 and `--skip-valid` was required because its installed schemas do not include pinned OVAL 5.12.3.

## Aggregate results

- Source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`
- XML files: **144** across 12 source families
- Completed OpenSCAP runs: **141**
- Engine execution errors: **3**
- Definition outcomes: **TRUE 62, FALSE 22, UNKNOWN 76, ERROR 4**
- Test outcomes: **TRUE 274, FALSE 173, UNKNOWN 302, ERROR 21**

| Family | XML | Completed | Engine errors | Def TRUE | Def FALSE | Def UNKNOWN | Def ERROR | Test TRUE | Test FALSE | Test UNKNOWN | Test ERROR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| agnostic | 35 | 34 | 1 | 40 | 3 | 1 | 1 | 180 | 115 | 1 | 10 |
| aix | 2 | 2 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 2 | 0 |
| asa | 2 | 2 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 2 | 0 |
| ios | 11 | 11 | 0 | 7 | 0 | 4 | 0 | 7 | 0 | 9 | 0 |
| iosxe | 11 | 11 | 0 | 7 | 0 | 4 | 0 | 7 | 0 | 10 | 0 |
| junos | 2 | 2 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 2 | 0 |
| linux | 16 | 14 | 2 | 1 | 7 | 4 | 2 | 19 | 19 | 10 | 4 |
| macos | 20 | 20 | 0 | 0 | 3 | 17 | 0 | 2 | 8 | 30 | 3 |
| panos | 2 | 2 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 2 | 0 |
| solaris | 6 | 6 | 0 | 0 | 2 | 4 | 0 | 2 | 3 | 15 | 1 |
| unix | 12 | 12 | 0 | 7 | 3 | 2 | 1 | 55 | 6 | 8 | 2 |
| windows | 25 | 25 | 0 | 0 | 4 | 32 | 0 | 2 | 22 | 211 | 1 |
| **Total** | **144** | **141** | **3** | **62** | **22** | **76** | **4** | **274** | **173** | **302** | **21** |

The JSON includes every observed source Test ID/result as well as every Definition ID/result. A file can contain multiple Definitions and Tests. These are engine outcomes, not source expected outcomes and not RI results.

## Root-cause observations

- Agnostic merge execution hit OpenSCAP's NULL component assertion for the known malformed merge Variable source; this is consistent with open source correction PR #7 and is not a SCAP-NG result.
- Linux SELinux boolean/security-context probes produced two engine execution errors in the restricted Ubuntu environment.
- Other Linux errors include unprivileged `/proc`/sysctl acquisition and missing RPM database effects; these remain host-authority diagnostics.
- Windows, macOS, Solaris, iOS, iOSXE, ASA, AIX, Junos and PAN-OS outcomes are wrong-platform diagnostics on Ubuntu, not platform qualification.

No source-authored expected outcomes were passed into OpenSCAP, and no result was promoted to RI equivalence. Raw result XML/logs remain external under the recorded output root and are not committed.

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

The harness refuses overwrite, uses no shell interpolation, enforces per-file limits, extracts Definition/Test outcomes without retaining Item values, and sanitizes host paths/identifiers in the committed ledger. This execution used the unprivileged Ubuntu environment and no sudo.
