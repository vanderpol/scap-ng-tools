# Issue #59 remaining 23 collected-field datatype audit

Canonical schema: `aece827964c785be77b088c3c61255a2d07fd9a9`; digest `578315d1e00bd39449ed597ed3d39555384276bd36198a54ca0b1e3c17e72829`. Pinned OVAL 5.12.3 source: `OVAL-Community/OVAL@2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`.

This audit does not convert or reclassify any Rule. It preserves the source Rule hash, Variable ID, Object graph, consumer operation and blocker.

## Disposition

| capability / field | Rules | distinct source shapes | recovered | blocked |
|---|---:|---:|---:|---:|
| `independent.environmentvariable` | 4 | 4 | 0 | 4 |
| `independent.shellcommand` | 13 | 13 | 0 | 13 |
| `windows.registry` | 6 | 3 | 0 | 6 |

## Pinned OVAL evidence

- `independent.shellcommand.subexpression`: collected Item and State are `EntityItemAnySimpleType` / `EntityStateAnySimpleType`; regex capture is lexical and does not establish a native type.
- `windows.registry.value`: Item is `EntityItemAnySimpleType`; OVAL requires the runtime Item datatype attribute to reflect the registry kind (`binary`, `int`, `string`, etc.). The source Objects here do not pin that runtime Item datatype. State value is also `EntityStateAnySimpleType` and may request `version` for a string registry value.
- `independent.environmentvariable.value`: Item and State are both `AnySimpleType`; the source Object selects name/pid only and supplies no runtime value datatype.
- No source operation in these 23 direct `object_component` expressions performs a lexical conversion before the value reaches the Variable. Source Variable `datatype=string` remains a compliance boundary, not a native cast.

## Rule-ID ledger

| Rule ID | Capability | source datatype | Object graph/pattern evidence | blocker/owner decision |
|---|---|---|---|---|
| `xccdf_mil.disa.stig_rule_SV-224861r991589_rule` | `independent.environmentvariable.value` | `string` | no pattern; selectors/runtime value type only | retain blocker |
| `xccdf_mil.disa.stig_rule_SV-205854r991589_rule` | `independent.environmentvariable.value` | `string` | no pattern; selectors/runtime value type only | retain blocker |
| `xccdf_mil.disa.stig_rule_SV-254280r991589_rule` | `independent.environmentvariable.value` | `string` | no pattern; selectors/runtime value type only | retain blocker |
| `xccdf_mil.disa.stig_rule_SV-278028r1182265_rule` | `independent.environmentvariable.value` | `string` | no pattern; selectors/runtime value type only | retain blocker |
| `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278382r1171898_rule` | `independent.shellcommand.subexpression` | `string` | ^# configuration\s+file\s+([a-zA-Z0-9_\-\.\/]*?\/nginx.conf):$; nginx: master process\s.*-c\s+(\S+) | retain blocker |
| `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278383r1171901_rule` | `independent.shellcommand.subexpression` | `string` | ^# configuration\s+file\s+([a-zA-Z0-9_\-\.\/]*?\/nginx.conf):$; nginx: master process\s.*-c\s+(\S+) | retain blocker |
| `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278385r1171907_rule` | `independent.shellcommand.subexpression` | `string` | ^# configuration\s+file\s+([a-zA-Z0-9_\-\.\/]*?\/nginx.conf):$; nginx: master process\s.*-c\s+(\S+) | retain blocker |
| `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278386r1171910_rule` | `independent.shellcommand.subexpression` | `string` | ^# configuration\s+file\s+([a-zA-Z0-9_\-\.\/]*?\/nginx.conf):$; nginx: master process\s.*-c\s+(\S+) | retain blocker |
| `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278387r1172701_rule` | `independent.shellcommand.subexpression` | `string` | ^# configuration\s+file\s+([a-zA-Z0-9_\-\.\/]*?\/nginx.conf):$; nginx: master process\s.*-c\s+(\S+) | retain blocker |
| `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278388r1171916_rule` | `independent.shellcommand.subexpression` | `string` | ^\s*access_log\s+(?!syslog:server)(\S+?)\s+\S+; | retain blocker |
| `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278392r1171928_rule` | `independent.shellcommand.subexpression` | `string` | ^\s*ssl_certificate_key\s+"*(.+)"*; | retain blocker |
| `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278397r1171943_rule` | `independent.shellcommand.subexpression` | `string` | ^# configuration\s+file\s+([a-zA-Z0-9_\-\.\/]*?)\/nginx.conf:$; nginx: master process\s.*-c\s+(\S+)\/\S | retain blocker |
| `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278399r1172775_rule` | `independent.shellcommand.subexpression` | `string` | ^# configuration\s+file\s+([a-zA-Z0-9_\-\.\/]*?\/nginx.conf):$; nginx: master process\s.*-c\s+(\S+) | retain blocker |
| `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278408r1171976_rule` | `independent.shellcommand.subexpression` | `string` | ^# configuration\s+file\s+([a-zA-Z0-9_\-\.\/]*?\/nginx.conf):$; nginx: master process\s.*-c\s+(\S+) | retain blocker |
| `xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-259592r961095_rule` | `independent.shellcommand.subexpression` | `string` | QueueDatabasePath" value="(\w): | retain blocker |
| `xccdf_mil.disa.stig_rule_SV-248526r958390_rule` | `independent.shellcommand.subexpression` | `string` | .*:[Bb]anner\s+(.+) | retain blocker |
| `xccdf_mil.disa.stig_rule_SV-230225r1184236_rule` | `independent.shellcommand.subexpression` | `string` | .*:[Bb]anner\s+(.+) | retain blocker |
| `xccdf_mil.disa.fso_rule_SV-284958r1208187_rule` | `windows.registry.value` | `string` | no pattern; selectors/runtime value type only | retain blocker |
| `xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214429r879717_rule` | `windows.registry.value` | `string` | no pattern; selectors/runtime value type only | retain blocker |
| `xccdf_mil.disa.stig_rule_SV-224970r958726_rule` | `windows.registry.value` | `string` | no pattern; selectors/runtime value type only | retain blocker |
| `xccdf_mil.disa.stig_rule_SV-205739r958726_rule` | `windows.registry.value` | `string` | no pattern; selectors/runtime value type only | retain blocker |
| `xccdf_mil.disa.stig_rule_SV-254391r958726_rule` | `windows.registry.value` | `string` | no pattern; selectors/runtime value type only | retain blocker |
| `xccdf_mil.disa.stig_rule_SV-278138r1182081_rule` | `windows.registry.value` | `string` | no pattern; selectors/runtime value type only | retain blocker |

## Owner decisions before conversion

1. **Shellcommand (13 Rules):** approve operation-directed interpretation of raw capture values, including malformed numeric lexical input, regex capture multiplicity/order, missing/error/incomplete command statuses and `var_check`.
2. **Windows registry (6 Rules):** provide runtime Item vectors carrying explicit registry datatype/type/status and define comparison interpretation; source Objects do not establish whether the value is string, integer, binary or version.
3. **Environment variable (4 Rules):** provide runtime Item datatype/status vectors and consumer-directed comparison semantics; source selection alone does not type the value.

The generic evaluator/consumer pathway and RI truth vectors remain unresolved. Stop before implementing conversions.
