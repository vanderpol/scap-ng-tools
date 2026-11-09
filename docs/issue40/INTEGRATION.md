# Publication safeguards and deployment verification

Issue #40 stays open for **final deployment verification**. Repository-level safeguards and qualified testing proceed independently of administrative API access. The four draft integrations remain unmerged; no deployment is claimed.

| Review | Independently testable safeguard | Evidence |
| --- | --- | --- |
| [Tools #41](https://github.com/vanderpol/scap-ng-tools/pull/41) | Pinned producer/schema/source, final byte validation/reproduction, admitted ZIP; historical sealer and direct-write denial | Required fixture-backed suite, tampering negatives, actual composite admission dry-run without upload |
| [Research #279](https://github.com/vanderpol/scap-ng-research/pull/279) | 186 historical uploads, 41 direct writers denied, standalone Contents API guard, 21 download adapters | Seven boundary tests; original workflow comparison; executable denial/staging witnesses |
| [Evidence #2](https://github.com/vanderpol/scap-ng-evidence/pull/2) | Unsupported full-65 release denied before download/reflow and release | Three tests; executable denial; original workflow reconstruction; unchanged historical Git trees |
| [Canonical #49](https://github.com/vanderpol/scap-ng/pull/49) | No baseline content publisher; tripwire for recognized future publication transports | Structured audit; 37 existing tests and regeneration checks |

The [entrypoint matrix](entrypoint-matrix.json) records 198 candidate source hashes/dependencies; candidates are not automatically active publishers. The [integration matrix](integration-matrix.json) records repository baselines and proposed safeguards. [Access observations and deployment status](integration-blockers.json) retain exact API results; the existing filename is retained for link compatibility.

Tools #41 depends on #39 (`f97ff187460f52da78bd16f5009f7d182664812b`), which includes #38. Review those dependencies before the gate. Historical sealer/denial actions are pinned to `053eeeb3b33e3ee5f683604fd66ae8c833450cd0`. Current admission is tested at the exact Tools PR head. The allowlist describes a proposed development source distribution, not a released package. Subsequent deployments must retain reviewed immutable pins. No merge is authorized by this report.

## What was and was not demonstrated

| Observation | Evidence level | Conclusion |
| --- | --- | --- |
| 227 Research publication steps and one Evidence release step lacked the new gate at their audited baselines | Source inspection | Demonstrated integration gap in those source trees; not a remotely executed security bypass |
| Historical/obsolete output, changed payloads and forged provenance fail current admission | Executed negative tests | The proposed gate rejects those concrete inputs without a qualified archive |
| Exact bound direct-write denials stop harmless local sentinels | Executed witnesses | The proposed command bodies stop before transport; no historical release body was executed |
| Ten Research API records report `active` but have no current-main file | Inventory observation | Does not establish that an old ref is executable, has write authority, or can bypass the gate |
| An old ref or external credential might publish outside the guarded path | Hypothetical, not demonstrated | No administrative misconfiguration or working bypass has been shown |

## Exact administrative inspection limitation

For each of `vanderpol/scap-ng`, `vanderpol/scap-ng-tools`, `vanderpol/scap-ng-research`, and `vanderpol/scap-ng-evidence`, the attempted endpoint was:

```text
GET /repos/{owner}/{repo}/actions/permissions/workflow
HTTP 403: Resource not accessible by integration
```

This endpoint reports `default_workflow_permissions` (repository default `GITHUB_TOKEN` permission setting) and `can_approve_pull_request_reviews` (whether Actions may approve pull-request reviews). Neither value could be inspected through this integration. The 403 establishes an **access limitation only**, with no conclusion about the configured values or their safety.

Branch/tag rulesets, protected-environment deployment policies, external credential scopes, publisher identities, and organization-level policies were not inspected by that endpoint. We did not obtain a denial for those separate settings and do not label them inaccessible or defective based on this response. Workflow-level `permissions:` declarations visible in source remain separately inspectable.

No elevated credentials, repository permission changes, new publisher identities, or administrative restrictions are requested or recommended on the basis of these observations. Administrative access is not a prerequisite for development, authoring validation, current admission tests, or their passing status. A regression executes successful admission and rejection with administrative HTTP access denied in the admission process.

## Final deployment checks

1. Review and deploy the repository changes in dependency order using the normal approved process; preserve frozen schemas and historical evidence.
2. Verify deployed workflow/action pins and run the fixture-backed qualification suite plus actual admission dry-run at the deployed commits. Confirm rejected inputs produce no qualified archive.
3. Check that the intended publication path uses the admitted bytes and historical paths remain explicitly unqualified or denied. Artifact quota can limit an actual upload check; do not retry quota-blocked uploads.
4. Record deployed commits, exact commands/results, and any concrete unguarded path discovered. Investigate a historical-ref bypass only when there is specific source/execution evidence; an API record alone is insufficient.

Close #40 after final deployment verification, or retain an explicit, concrete deployment gap. The administrative inspection limitation alone does not block normal work or qualified testing. Full-65 current qualification remains unsupported and fails closed. No release, scanner-equivalence, or SCC claim is made.
