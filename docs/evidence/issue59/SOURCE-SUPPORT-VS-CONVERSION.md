# Source support versus conversion - historic 98-Rule blocker audit

This is a new normative-source crosswalk, not a converter rerun. The original 98-Rule receipt remains unchanged.

Original benchmark source commit: 8c8e5dff860af6b1290ee9273a282db24278f8d5
Original canonical schema commit: aece827964c785be77b088c3c61255a2d07fd9a9
Normative reference: [OVAL 5.12.3 Windows Definitions](https://oval-community-guidelines.readthedocs.io/en/latest/oval-schema-documentation/windows-definitions-schema.html)

| Independent OVAL source-status axis | Rules |
|---|---:|
| Verified deprecated by pinned OVAL 5.12.3 | 71 |
| Normative status requires original-source/XSD review | 27 |
| **Total historical blocked native Rules** | **98** |

The 66 Windows accesstoken_test and five Windows user_test entries were deprecated in OVAL 5.11. All 98 remain historically unconverted. Replacements are NOT asserted behaviorally equivalent.

The other 27 are NOT yet proven nondeprecated; check original OVAL source versions, exact QNames, referenced Object/State and behaviors. Never infer deprecation from lack of a native mapping.

## Remaining source-status verification queue

| Original source Rule | Native blocker group |
|---|---|
| xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-278400r1172752_rule | unsupported-capability |
| xccdf_mil.disa.fso_rule_SV-225223r961038_rule | schema-semantic |
| xccdf_mil.disa.fso_rule_SV-225230r1117185_rule | schema-semantic |
| xccdf_mil.disa.fso_rule_SV-225232r1050651_rule | schema-semantic |
| xccdf_mil.disa.fso_rule_SV-225234r1188289_rule | schema-semantic |
| xccdf_mil.disa.fso_rule_SV-225235r960891_rule | schema-semantic |
| xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-259637r961608_rule | schema-semantic |
| xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-259704r961608_rule | schema-semantic |
| xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218795r960963_rule | schema-semantic |
| xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218814r1067589_rule | unsupported-construct |
| xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218741r1022677_rule | unsupported-capability |
| xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218742r1022679_rule | unsupported-capability |
| xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218752r1111807_rule | unsupported-construct |
| xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218771r1192784_rule | schema-semantic |
| xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218781r1022700_rule | unsupported-capability |
| xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214416r879627_rule | schema-semantic |
| xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214451r879567_rule | unsupported-capability |
| xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214452r879568_rule | unsupported-capability |
| xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214463r879643_rule | unsupported-construct |
| xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214495r879587_rule | unsupported-capability |
| xccdf_mil.disa.stig_rule_SV-224975r958524_rule | schema-semantic |
| xccdf_mil.disa.stig_rule_SV-205723r1137695_rule | schema-semantic |
| xccdf_mil.disa.stig_rule_SV-254396r1137695_rule | schema-semantic |
| xccdf_mil.disa.stig_rule_SV-278143r1182092_rule | schema-semantic |
| xccdf_mil.disa.stig_rule_SV-221653r1015161_rule | unsupported-construct |
| xccdf_mil.disa.stig_rule_SV-221718r991590_rule | unsupported-construct |
| xccdf_mil.disa.stig_rule_SV-214799r991589_rule | unsupported-construct |

The machine-readable source-status-crosswalk.json retains the original Rule identities, native conversion dispositions, diagnostic text and deprecation authority. Per-Rule original XML hashes and a current-main source rebuild remain to be qualified.
