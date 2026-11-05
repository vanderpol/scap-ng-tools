# Issue #28 remaining root causes

The complete ledger now groups generated schema diagnostics by stable root cause. The table below is the mutually exclusive **primary blocker** accounting; every genuinely blocked Rule appears exactly once. Raw diagnostics, including generated ASTs and filenames, remain on each Rule in `COMPLETE-LEDGER.json`.

| Category | Primary root cause | Rules | Representative source Rule |
|---|---|---:|---|
| unsupported-capability | unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken_test | 125 | `xccdf_mil.disa.stig_rule_SV-220956r958726_rule` |
| schema-semantic | native function contract admission: count | 37 | `xccdf_mil.disa.stig_rule_SV-274160r1120663_rule` |
| unsupported-construct | XCCDF Value operator requires an explicit constraint adapter | 36 | `xccdf_mil.disa.fso_rule_SV-226057r794277_rule` |
| unsupported-construct | multiple aggregation components need an approved collection expression | 30 | `xccdf_mil.disa.stig_rule_SV-251546r1201983_rule` |
| unsupported-capability | unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}wmi_test | 20 | `xccdf_mil.disa.fso_rule_SV-226065r794383_rule` |
| schema-semantic | native function contract admission: split | 19 | `xccdf_mil.disa.stig_rule_SV-219147r958472_rule` |
| unsupported-capability | unsupported object capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}wmi_object | 14 | `xccdf_mil.disa.fso_rule_SV-225230r1117185_rule` |
| unsupported-capability | unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}user_test | 8 | `xccdf_mil.disa.stig_rule_SV-220952r1051038_rule` |
| unsupported-construct | invalid original pattern-path recursion attributes | 7 | `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218801r961083_rule` |
| schema-semantic | native function contract admission: arithmetic | 3 | `xccdf_mil.disa.stig_rule_SV-274067r1120653_rule` |
| schema-semantic | native Variable declared/derived datatype mismatch | 3 | `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218762r1192782_rule` |
| unsupported-construct | check-export source/Variable datatype mismatch | 2 | `xccdf_mil.disa.fso_rule_SV-226276r794552_rule` |
| unsupported-construct | unsupported State field/namespace | 2 | `xccdf_mil.disa.stig_rule_SV-221653r1015161_rule` |
| unsupported-capability | state capability mismatch: oval:navy.navwar.niwcatlantic.scc.nginx:ste:27840004 | 1 | `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278400r1172752_rule` |
| schema-semantic | native traversal contract admission | 1 | `xccdf_mil.disa.fso_rule_SV-225223r961038_rule` |
| schema-semantic | native function contract admission: substring | 1 | `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-259592r961095_rule` |
| unsupported-construct | Variable cast outside bounded proof | 1 | `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218814r1067589_rule` |
| unsupported-capability | state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.10.site:ste:21874102 | 1 | `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218741r1022677_rule` |
| unsupported-capability | state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.10.site:ste:21874205 | 1 | `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218742r1022679_rule` |
| unsupported-capability | state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.10.site:ste:21878101 | 1 | `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218781r1022700_rule` |
| unsupported-capability | state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.8.5.site:ste:80 | 1 | `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214451r879567_rule` |
| unsupported-capability | state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.8.5.site:ste:93 | 1 | `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214452r879568_rule` |
| unsupported-capability | state capability mismatch: oval:navy.navwar.niwcatlantic.scc.ms.iis.8.5.site:ste:180 | 1 | `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214495r879587_rule` |
| unsupported-construct | Assessment Input function composition requires a supported typed expression | 1 | `xccdf_mil.disa.stig_rule_SV-221718r991590_rule` |

**Primary total: 317 genuinely blocked Rules.** The mutually exclusive classification remains 6,785 automated converted but unproved, 1,581 manual-only, 317 genuinely blocked, 209 intentionally excluded, and 0 independently proved out of 8,892 Rules.

## Overlapping feature diagnostics and intentional exclusions

| Feature | Source Rules (non-excluded) | Primary/qualification |
|---|---:|---|
| Deprecated access-token Tests | 127 | 125 primary Rules; intentionally unsupported; no native equivalent fabricated |
| Deprecated legacy `wmi_*` | 37 | 20 primary Test Rules and 14 primary Object Rules; intentionally unsupported |
| Supported `wmi57_*` | 169 | Tracked separately as supported WMI; no legacy WMI mapping inferred |
| OVAL `count` | 37 | Candidate preserves operands, but active schema/compiler admission is missing |
| Float ordered comparisons | 10 | Finite binary32 conversion recovered; all remain independently unproved |
| SQLEXT-dependent SQL | 209 | Intentionally excluded from conversion scope; source retained and counted separately |

These feature rows are diagnostic and may overlap a Rule; they are not added to the 317 primary total.

## Genuine language and contract gaps

- XCCDF relational Value constraints require a typed Input/Parameter relation contract; allowed-values-only lowering is not faithful.
- Multi-component `unique`/`merge` require collection-expression admission that preserves source order, duplicates, empty values, and error/unknown propagation.
- Native function admission remains pending for arithmetic, `count`, `split`, `substring`, and related recovered forms. The pinned active Assessment schema rejects canonical function calls.
- Native traversal admission remains pending for one registry traversal shape; pattern paths, full paths, and upward recursion remain fail-closed.
- Three Rules have a declared/derived Variable datatype mismatch, and one has an explicit unsupported cast boundary. No silent cast is applied.
- Remaining IIS/NGINX capability mismatches, unsupported `windows.user_*`, and composed Input expressions require approved mappings/contracts.

## Verification boundary

The ledger performs pinned-schema validation and source tracing. This tools branch does not provide compiler/scanner execution or independent OVAL-result comparison. YAML validity, schema validity, and conversion admission therefore do not promote any Rule to proved.
