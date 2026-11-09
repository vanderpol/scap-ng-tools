# Publication integrations and remaining owner/admin work

Issue #40 remains **not complete**. Source guards are proposed in four draft PRs; none is deployed. [Machine-readable matrix](integration-matrix.json) records exact baselines, proposed heads, and sink counts. [Access/ref blockers](integration-blockers.json) retain the read-only API evidence.

| Review | Proposed boundary | Required evidence |
| --- | --- | --- |
| [Tools #41](https://github.com/vanderpol/scap-ng-tools/pull/41) | Pinned converter → actual schema validation → independent byte reproduction → admitted ZIP; historical sealer and denial shared actions | Required fixture-backed tests and actual composite action dry-run, no upload |
| [Research #279](https://github.com/vanderpol/scap-ng-research/pull/279) | 186 historical uploads; 41 direct writers denied; standalone Contents API writer denied; 21 download namespace adapters | Six tests, full baseline workflow comparison, real denial/staging witnesses, structured sink audit |
| [Evidence #2](https://github.com/vanderpol/scap-ng-evidence/pull/2) | Full-65 release fails closed before download and before release | Three tests, actual denial, original workflow reconstruction and unchanged runs/manifests/summaries Git trees |
| [Canonical #49](https://github.com/vanderpol/scap-ng/pull/49) | No current publisher at baseline; reject future bypass sinks | Structured audit; existing 37 local tests and regeneration checks |

Tools #41 is stacked on Tools #39 (`f97ff187460f52da78bd16f5009f7d182664812b`), which includes Tools #38. Review/land those dependencies before the gate. The policy's source-distribution pin is a proposed allowlist admission, not a claim that the unmerged commit is already a released package. Review Tools #41's immutable shared action commit `053eeeb3b33e3ee5f683604fd66ae8c833450cd0` before dependent integrations. Integrations can then be reviewed independently; enforce server controls before representing repository-wide coverage as complete. No PR is merged by this work.

Initial CI runs used GitHub's synthetic merge ref. The final validation lanes explicitly check out and assert the PR head SHA (or push SHA), avoiding ambiguity about tested bytes. Earlier passing merge-ref runs remain evidence for their named tested commits, never substituted for the final exact-head receipt. New qualification lanes perform no uploads. Existing unrelated historical lanes may upload explicitly unqualified artifacts and may encounter quota limits; they are not retried or represented as current qualification.

## Decision needed for server enforcement

Four Actions permission-policy reads returned HTTP 403. The Research API reports 222 active workflow records; ten have no file in the 212-workflow main tree. Their old-ref behavior, inherited credentials, environment restrictions, and out-of-band publishers are **unverified**. A static inventory or new main workflow cannot constrain those permissions. Admission manifests provide reproducibility under a trusted runner and sink; they are not signed publisher authentication.

| Alternative | Effect and limitation |
| --- | --- |
| Main-branch guards only | Covers the proposed source tree after deployment. Leaves old refs/credentials unverified; insufficient to close #40. |
| Restrict official publication authority to a reviewed publisher identity and allowed refs/environments; retain historical refs | Recommended. Requires owner/admin access and execution-policy evidence. Historical bytes remain readable; old research tokens cannot qualify new content. |
| Rewrite/delete historical refs or rely on artifact names/hashes alone | Not recommended. Rewriting destroys provenance; names and unsigned hashes do not establish authority. |

The smallest remaining owner/admin action is to identify the official content-publishing credentials/environments, inspect the ten active historical workflow records, and supply verifiable ref/token policy or apply reviewed restrictions. Check that a guarded current-ref admission is allowed while an old-ref publication attempt lacks authoritative write permission. Use harmless namespace/sentinel tests; do not publish or rewrite old content as a probe. Disabling an obsolete workflow record can be a reviewed mitigation, but is not a substitute for credential/ref restrictions.

Until those controls and the reviewed integrations are deployed and tested, all four repositories retain an explicit deployment/ref-policy blocker. Full-65 current qualification remains unsupported and denied. Historical 65-Benchmark content and prior proofs are preserved without promotion. No scanner-equivalence, release-readiness, or SCC claim is made.
