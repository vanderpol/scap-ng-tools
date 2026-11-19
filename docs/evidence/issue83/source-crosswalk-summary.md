# Issue #83 source crosswalk

This report is generated from immutable signed SCAP 1.4 source ZIPs. It is a source inventory and converter-loss audit, not runtime or OVAL equivalence proof.

- Source commit: `8c8e5dff860af6b1290ee9273a282db24278f8d5`
- Archives: **65**
- Source Rules: **8892**
- Rules with `requires`/`conflicts`: **0**
- `requires` rows: **0**; `conflicts` rows: **0**
- Groups with relationships: **0** (requires **0**, conflicts **0**)

## Result

The pinned 65-archive corpus contains no non-empty `Rule/requires` or `Rule/conflicts` relationships, and the separately audited Group relationship ledger is also measured. These are measured zeros, not evidence that the converter may drop relationships: source relationships are preserved for Rules and Groups are failed closed until a canonical non-flattening Group mapping exists. The test fixture exercises positive and negative source relationship elements.

## DISA extended description mapping

Literal publisher XML inside XCCDF `description` is retained without data loss:

| Source field | Native location | Preservation |
|---|---|---|
| `VulnDiscussion` | `rule.discussion` | exact source text retained; structured `rule.extensions.disa` is held |
| `FalsePositives` | `rule.discussion` | exact source text retained; structured `rule.extensions.disa` is held |
| `FalseNegatives` | `rule.discussion` | exact source text retained; structured `rule.extensions.disa` is held |
| `Documentable` | `rule.discussion` | exact source text retained; structured `rule.extensions.disa` is held |
| `Mitigations` | `rule.discussion` | exact source text retained; structured `rule.extensions.disa` is held |
| `SeverityOverrideGuidance` | `rule.discussion` | exact source text retained; structured `rule.extensions.disa` is held |
| `PotentialImpacts` | `rule.discussion` | exact source text retained; structured `rule.extensions.disa` is held |
| `ThirdPartyTools` | `rule.discussion` | exact source text retained; structured `rule.extensions.disa` is held |
| `MitigationControl` | `rule.discussion` | exact source text retained; structured `rule.extensions.disa` is held |
| `Responsibility` | `rule.discussion` | exact source text retained; structured `rule.extensions.disa` is held |
| `IAControls` | `rule.discussion` | exact source text retained; structured `rule.extensions.disa` is held |

The source ledger has the eleven-field DISA payload on 8867 Rules; 25 Rules have publisher-looking descriptions that require source-specific review. Per-Rule field hashes are retained in JSON. `rule.discussion` retains the original description text for compatibility.

## Holds

- The OVAL XSD declaration inventory (when supplied) is intentionally `unclassified`; XSD declaration names are not native support proof.
- Canonical schema changes are out of scope for this Tools increment; any missing native representation is a canonical-language decision for `scap-ng` #80.
- Native conversion output and RI execution are separate qualification stages.
