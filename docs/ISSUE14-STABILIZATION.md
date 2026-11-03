# Issue14 stabilization and bounded default repair — 2026-11-03

Follow-up: the [ten-case float investigation and owner decision packet](ISSUE14-FLOAT-DECISION.md)
records **10 blocked → 10 blocked, 0 recovered**, with all ten real manual
Assessments preserved. Native typed syntax/experimental compilation succeeds;
binary32 observed-value semantics remain an owner decision. All counts and prior
proof levels below remain unchanged; the original evidence files are retained.

This follows the [new owner direction](https://github.com/vanderpol/scap-ng-tools/issues/14#issuecomment-6602501616).
No schema, mapping, datatype representation, cardinality, Input binding,
function vocabulary, collector or editor PR36 change is included. Earlier PR15,
PR16, original sources and proof receipts remain immutable. This branch is a
small successor to portable PR16, not a replacement release or new full65 library.

## The one implementation defect repaired

Windows Server2016 SV-224994 uses this original empty State field:

```xml
<stdout_line check_existence="none_exist" operation="equals"/>
```

The recovery visitor rejected it, while already admitting the otherwise
identical field with omitted operation. Official OVAL5.12.3
`EntityAttributeGroup` explicitly defaults operation to equals, inherited through
EntitySimpleBaseType / EntityStateSimpleBaseType. The exact official source is
`2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`; the signed Windows ZIP is
`76cf6a14fefd077136d9a23a6ba4a30c82a0b254adc8cf2abd88592dc30776a8`.

The opt-in recovery visitor now removes only that redundant default from a
copy, then invokes the unchanged absence adapter. Both original implicit and
explicit source forms produce `{"values_found":"none"}`. The original source
node/hash/attributes remain in provenance. No values or statuses are computed.
Selectors, records, child nodes, nonempty/whitespace text, Variables, extra
attributes and other comparators remain strict. The frozen strict visitor is
unchanged. No cardinality or unknown/error/incomplete behavior is redefined.

Source tests pin actual positive/negative node identities, ZIPs and parent IDs:
[small witnesses](../tests/fixtures/issue14-boundary-witnesses.json). They include
an original implicit absence, the explicit-default case, a pattern-bearing
absence that still rejects, a numeric integer projection, an explicit float that
still rejects, and deprecated RPM field rejection. The upstream XSD default is
checked independently, not copied from the new implementation.

The complete Rule now retains its source automated default and real manual
choice, with five native documents / one program / one Test. External native
compiler and independent package/source comparison pass at
`7e26f8da44a81ae96135eca837e611a3f99f9c28`; [receipt](evidence/issue14-stabilization/absence-qualification.json).
This is a default-attribute AST projection and package consistency qualification,
not full original-OVAL semantic proof, scanner execution or publisher trust.
The dated owner authorization permits repairs within existing approved syntax;
this packet remains available for human review and does not ratify new semantics.

## Complete remaining48 replay and denominator control

[Before at PR16](evidence/issue14-stabilization/remaining48-before.json) and
[current source-backed ledger](evidence/issue14-stabilization/remaining48.json)
cover exactly the48 remaining cases from PR15. The nine residual function pilot
cases are a **subset**, not nine extra Rules. Before this repair:2 Solaris drafts,
46 blocked. After:3 automated drafts,45 blocked. All48 manual methods remain
accounted for; unsupported source defaults are not silently switched to manual.
The two prior Solaris package receipts stay at their original qualified pins.

Across the original selected143 Rules:78 automated drafts /20 manual-only /45
blocked,98 complete Rule projections,78 programs/214 Tests in combined receipts.
The historical automated backlog becomes381 (45 attempted +336 held), with41
recoveries from the original422. This is not a new current validation claim for
the other8749 source Rules or the old4258 proofs.

### Ranked remaining causes, based on actual witnesses

| Cases | Source fact / priority | Safe next disposition |
| --- | --- | --- |
|10| explicit float comparisons, e.g. float greater-than-or-equal10.0; native typed-float syntax exists but the source representation adapter deliberately rejects it | highest repeated adapter opportunity; needs a reviewed float lexical/representation boundary, never float→integer coercion |
|8| none_exist with pattern match and literal pattern | preserve fail-closed; do not discard comparator/value or change status/cardinality semantics |
|7| original legacy wmi_object, including five residual function pilot cases | no WMI substitution or fallback shellcommand; separately scoped source/capability work |
|4| Test/Filter State family mismatches: file Test→shellcommand State; appcmd Tests→variable States; appcmd Object→appcmdlistconfig Filter State | exact related nodes are in ledger; source/link correction review, not capability relabelling |
|3| all_exist population gate in arithmetic pilot | separate population qualification; latent numeric-function result/string declaration mismatch also retained |
|3| pattern-path recursion attributes rejected by source contract | source correction; no silent rewrite of paths or recursion depth |
|2| deprecated md5_differs field | canonical mapping explicitly says migration_error_replaced_by_filedigest_differs; upstream replacement prose does not authorize overriding that policy |
|2| command acquisition comparator/type mismatch | keep exact operation/cast; no broad parameter coercion |
|2| XCCDF Value operator disagrees with OVAL consumers | preserve both constraints; no invention of bounds or consumer defaults |
|2| check-export Value/Variable datatype disagreement | no silent cast or invented binding |
|1| source Variable cast at acquisition boundary | explicit representation/type review required |
|1| Input function composition in Oracle7 arithmetic | current expression grammar does not admit direct Input operands; no expansion here |

The ranked ledger classifies root source evidence; it does not assert all future
blockers have been exhausted after those roots. No new language decision is
silently implemented to obtain a better count.

## Pinned stacks and 0.4 go/no-go

[Read-only PR snapshot](evidence/issue14-stabilization/pr-stack.json) records all
exact bases/heads, draft state, review state and mergeability. At inspection all
nine integration PRs remain open/draft, with no submitted approvals. Mergeable
is a GitHub graph property, not acceptance or readiness. No PR was merged,
retargeted, rebased or force-pushed in this consolidation.

| Dependency | Exact head |
| --- | --- |
| canonical9 →11 | d4e477998cda438a1e53a7c3c84123ec92e5ba1f →246a8d37cc54875386768a7d76b60a6f9c01d013 |
| tools13 →15 →16 | 1c8aa287808f3ad0aa3d5e8aa610d800e8862c22 →72f7ec2317c409362393c9c0d74b19d081b38f05 →8f5251dcd1062ed29e33b8e9ef72f2f619d83a0d |
| compiler272 →275 | b34db42f40d801662fb08ab6c64be36dad03327b →7e26f8da44a81ae96135eca837e611a3f99f9c28 |
| editor26 →34 | f65a85bdedb23e634244f1071eaf069da33358fc →e20a64725c979011883fc1c35e13a4e76c7c4b70 |

The editor's metadata pin stays on the already qualified public schema/tools
boundary. This recovery-only fix does not alter its exported resources or require
an office UI change. PR36 is independent and untouched.

- **DRAFT review:** source-pinned selected coverage, real manual choices and package receipts are available; [Firewall parity](evidence/issue14-stabilization/firewall-parity.json) confirms all64 native documents remain exactly equal to the earlier pilot, with21/21 Rules,20 automatic drafts and21 manual methods. Existing tests cover all38 PR15 recovery cases.
- **Integration/merge:** no readiness claim. Human review of pending Input/function contracts, dependency-safe integration and exact updated-pin remote receipts are still required. Main does not contain these draft stacks.
- **New full65/current editor corpus:** no-go under this task. Original inventory and immutable old proofs remain separate; no old archive is promoted.
- **Board/production/scanner:** no-go. Full original-source semantics, runtime acquisition/value/status behavior, policy/CPE execution, live scanner results and publisher trust are not established by these checks.
- **Owner decisions:** if further recovery is desired, separately decide float representation, comparator-bearing absence, deprecated-field policy, WMI source/capability scope, population semantics and direct Input expression composition. No additional function is authorized by this PR.

## Validation and reproducibility

The same canonical family, semantic pack and235-resource metadata pins are kept.
Legacy0.3, Result wires, frozen runtime18 files and all535 strict document/trace/
coverage/admission goldens remain unchanged. Fresh **59 portable tests /zero skips**, including all six boundary tests, pass.
The complete48 replay and Firewall parity pass. Log identities are in the
[compact validation receipt](evidence/issue14-stabilization/local-validation.json);
exact remote source-head checks follow in the PR conversation.

```sh
PYTHONPATH=src python scripts/triage_recovery_blockers.py \
  --schema-root /path/to/canonical246a8d3 \
  --source-root /path/to/pinned/Archive/2026_Q3 --output /tmp/new-triage48
```

The default fixture contains all48 exact Rule/ZIP pins. The script refuses an
existing output, never rewrites source, checks native drafts in memory and emits
only a compact ledger with source-node witnesses. Compiled/proof/scanner flags
stay false in that classification run; separate qualification receipts are named
above. It is not a library generator or scanner. Large raw outputs/logs remain
outside Git; small identities in comments are not presented as remotely
verifiable full proof artifacts.

Separately reviewed CI [private PR277](https://github.com/vanderpol/scap-ng-research/pull/277)
reduces routine uploads, preserves output/error checks and mandatory matrix
transfers. On its first exact head, current Windows/Linux, canonical fast,
clean extract, sync, documentation and policy jobs pass. Six-source transfer
uploads remain quota-blocked; an unchanged non-current pinned historical lane
retains its own test failures. New routine success never relabels old failed
artifact gates. No quota retry spam, deletion, release or unverifiable proof claim.
