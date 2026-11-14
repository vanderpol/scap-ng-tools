# Issue #59 `textfilecontent.subexpression` pattern review

This review covers all 85 remaining `independent.textfilecontent.subexpression` datatype regressions. It uses OVAL Community 5.12.3 at commit `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706` and the same canonical SCAP-NG pin.

## Result

- Distinct source pattern shapes: **20**
- Source Rules reviewed: **85**
- Recovered: **0**
- Retained blocked: **85**
- Scanner/RI equivalence: **not claimed**

## OVAL evidence

- `independent-system-characteristics-schema.xsd:383-387`: collected Item `subexpression` is `EntityItemAnySimpleType`.
- `independent-definitions-schema.xsd:1910-1914`: State `subexpression` is also `EntityStateAnySimpleType`.
- The Object `pattern` is a regex (`pattern match`) and is itself a string State entity; it does not type the captured subexpression.
- `oval-definitions-schema.xsd:533-534` and the OVAL VariableType guidance state that a Variable’s values must comply with its declared datatype and an error is reported otherwise. They do not define a conversion from the collected Item.

Therefore no reviewed operation in these 20 shapes establishes a native collected datatype or lexical conversion before the values enter the downstream Variable. The source `datatype="int"` declarations and digit-only regexes are compliance constraints, not permission for the converter to insert an implicit cast.

## Pattern decisions

| # | Rules | Variable types | Pattern | Pattern attrs | Decision |
|---:|---:|---|---|---|---|
| 1 | 2 | string | `^(.*)$` | `{"datatype": "string", "operation": "pattern match"}` | retain blocker |
| 2 | 1 | string | `^(?i)[ -]*audit-log-path=(\S+)` | `{"operation": "pattern match"}` | retain blocker |
| 3 | 4 | string | `^([^:]*):[^:]*:[^:]*:0*:` | `{"operation": "pattern match"}` | retain blocker |
| 4 | 1 | string | `^[ -]*audit-policy-file=\s*(\S+)` | `{"operation": "pattern match"}` | retain blocker |
| 5 | 3 | string | `^[^#\n]*\bclientCAFile:\s*(\S+)` | `{"operation": "pattern match"}` | retain blocker |
| 6 | 2 | string | `^[^#\s\:]+:[^#\s\:]*:([0-9]+):` | `{"operation": "pattern match"}` | retain blocker |
| 7 | 1 | int | `^[^:#]*:[^:]*:(\d+)` | `{"operation": "pattern match"}` | retain blocker |
| 8 | 4 | string | `^[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:([^:]*?):.*` | `{"operation": "pattern match"}` | retain blocker |
| 9 | 2 | int | `^[^:]+:[^:]*:(\d+):` | `{"datatype": "string", "operation": "pattern match"}` | retain blocker |
| 10 | 1 | string | `^\n*[\s#]*banner\s+(\S+)$` | `{"operation": "pattern match"}` | retain blocker |
| 11 | 2 | string | `^\s*([^#:]*):` | `{"datatype": "string", "operation": "pattern match"}` | retain blocker |
| 12 | 4 | string | `^\s*dir\s*=\s*(.*)\s*$` | `{"operation": "pattern match"}` | retain blocker |
| 13 | 20 | string | `^\s*log_file\s*=\s*(\S+)/\S+\s*$` | `{"datatype": "string", "operation": "pattern match"}` | retain blocker |
| 14 | 21 | string | `^\s*log_file\s*=\s*(\S+)\s*(?:#.*)?$` | `{"operation": "pattern match"}` | retain blocker |
| 15 | 2 | int | `^adm:[^:]*:([0-9]+):` | `{"datatype": "string", "operation": "pattern match"}` | retain blocker |
| 16 | 2 | int | `^adm:[^:]*:([0-9]+):` | `{"operation": "pattern match"}` | retain blocker |
| 17 | 1 | int | `^etcd:[^:]*:(\d+):` | `{"operation": "pattern match"}` | retain blocker |
| 18 | 4 | int | `^syslog:[^:]*:([0-9]+):` | `{"datatype": "string", "operation": "pattern match"}` | retain blocker |
| 19 | 4 | int | `^syslog:x:([0-9]+):[0-9]+::.*:.*$` | `{"datatype": "string", "operation": "pattern match"}` | retain blocker |
| 20 | 4 | int | `^systemd-journal:[^:]*:([0-9]+):` | `{"operation": "pattern match"}` | retain blocker |

## Required owner decision

For each pattern (or a single reviewed rule covering all 20), the owner must choose one of:

1. approve a canonical typed collected-Item/result contract for `subexpression`, including lexical parsing, invalid-value behavior, empty/missing/error/unknown/incomplete status propagation, multiplicity and downstream `var_check`; or
2. provide a pinned OVAL/RI semantic rule and truth vectors that establish an explicit lexical conversion before the Variable expression; or
3. retain the blocker and revise the source authoring to use an explicitly typed native expression without relying on the OVAL declaration.

Until that decision is reviewed, all 85 original Rule IDs remain blocked. The complete per-Rule source IDs, hashes, Variable IDs, consumer operations and source objects are in `textfilecontent-subexpression-patterns.json`.
