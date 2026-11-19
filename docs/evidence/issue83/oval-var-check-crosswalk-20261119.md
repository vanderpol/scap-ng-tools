# OVAL `var_check` source crosswalk

This source-pinned crosswalk records authored `var_check` values and their current native value-match projection. It is not runtime qualification or independent OVAL equivalence proof.

- Source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`
- Source root: `SCAP_1.4/OVAL_Test_Content`
- Tools converter: `a150d36b0d259a74cdbcd1887a0943687e222e27`
- Canonical 0.4.1: `5ee55288b369da26f308f40813e545b78dff2753`
- Schema family SHA-256: `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`

## Inventory

- Source elements with `var_check`: **121**
- Test-linked rows: **120**
- Explicit orphan component rows: **3**
- Rows including shared-component links: **123**
- Tests with `var_check`: **58**
- Definitions referenced: **21**

| Source family | Rows |
|---|---:|
| `agnostic` | 31 |
| `linux` | 7 |
| `macos` | 2 |
| `solaris` | 1 |
| `unix` | 15 |
| `windows` | 67 |

| Authored value | Count | Native projection |
|---|---:|---|
| `all` | 66 | `every` |
| `at least one` | 33 | `one_or_more` |
| `none exist` | 1 | `none` |
| `none satisfy` | 6 | `none` |
| `only one` | 17 | `exactly_one` |

## Orphan source components

These components contain authored `var_check` but are not reachable from a Test in the same source document. They remain explicit source rows and are not treated as converted or executable.

| Source path | Component | Element | `var_check` | Variable |
|---|---|---|---|---|
| `SCAP_1.4/OVAL_Test_Content/unix/oval-def_set-unix.xml` | `oval:org.mitre.oval.test:ste:746` | `path` | `only one` | `oval:org.mitre.oval.test:var:134` |
| `SCAP_1.4/OVAL_Test_Content/unix/unix-def_password_test.xml` | `oval:navy.navwar.niwcatlantic.scc.test:obj:24` | `username` | `all` | `oval:navy.navwar.niwcatlantic.scc.test:var:549` |
| `SCAP_1.4/OVAL_Test_Content/windows/oval-def_set-windows.xml` | `oval:org.mitre.oval.test:ste:746` | `path` | `only one` | `oval:org.mitre.oval.test:var:134` |

## Semantic boundaries

- Missing `var_check` defaults to OVAL `all`; this ledger covers explicit authored values only.
- `none exist` is retained as source identity and currently projects to native `value_match: none`; this requires runtime semantic qualification.
- Variable values are represented only by cardinality and a SHA-256 digest; source values are not copied into the compact report.
- No source expectation is supplied to the converter or evaluator.
- Runtime qualification: **not run**; independent equivalence: **not proved**.
