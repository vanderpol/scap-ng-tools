# RHEL 9 shellcommand simplification audit

**Owner review: recommend no production replacements from this audit.** All
415 converted automated RHEL 9 Assessments are inventoried. The final complex
cohort is83 Assessments (20%). Ten of the strongest bounded-utility avenues were
reviewed in depth; none meets all nine replacement criteria. Nine proposed
sketches save less than70% of the measured structure. The one larger apparent
reduction discards obligations and enumerates audit rules. A smaller YAML file
is not a lossless simplification when it stops checking required conditions.

Issue: [tools #34](https://github.com/vanderpol/scap-ng-tools/issues/34).
This is analysis only. Production content, original OVAL, manual choices,
provenance and all historical proof receipts are unchanged. No new scanner
equivalence, source-proof promotion, release or replacement implementation is
claimed. The ten proposed YAMLs are explicitly **UNAPPROVED review sketches**,
including rejected counterproposals; they are not ten recommendations.

## Exact scope and pin qualification

At inspection, public evidence main was `7dc17f0982cdb5b17281f8f8e4373dbd87f86f58`.
Its published65-stream normalized archive is still the **October30** snapshot.
The current tree's archive Git blob `b8575390c6f695e31f4d95d3ec29816386c46d93`
matches the local archive; SHA-256 is also checked before analysis. No newer
full65 amended-grammar library was found in that pinned evidence tree. This
audit therefore uses the actual published corpus, **not an invented current
grammar regeneration**. The preserved originals predate grouped Item/field
requirements; the proposed sketches use the separately inspected current schema.

| Input | Exact pin / identity |
| --- | --- |
| [65-stream library](https://github.com/vanderpol/scap-ng-evidence/blob/7dc17f0982cdb5b17281f8f8e4373dbd87f86f58/runs/v04-library/2026-10-30-all65-normalized-review-ff69d46b3/scap-ng-v04-normalized-library-review.zip) | SHA256 `a01ea589501bf8a53e5df68e50ca9478f19543d2bd3844546667fde743c28d8c` |
| Library exporter | `03ddc6beda8dcda5ff57439b0c3d7a2d12763d1b`; source snapshot `ff69d46b36e05e45074a5e7f43bf2ef3cf464ddf` |
| [Original NIWC RHEL9 V2R9 enhancedV13 ZIP](https://github.com/niwc-atlantic/scap-content-library/blob/8c8e5dff860af6b1290ee9273a282db24278f8d5/Archive/2026_Q3/U_RHEL_9_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip) | SHA256 `70aa6a16221df2c53b094b11b48b16aca1f6d7147c11123b655659ca7711dbb5` |
| [Official DISA manual, V2R9](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_9_V2R9_STIG.zip) | Direct Cyber Exchange HTTP200 ZIP, SHA256 `1875de2543d01695c5a346c51888cc336113e9199bfe6726d74a08de286ca1ae` |
| Inspected canonical schema | `7354a24cdbfe18321153ccaef5d772801a10cd71`; all structural-check schema hashes retained |
| Tools base / existing portable CI schema | `c5f5b215000a1f9149ed56541320da5d7918c94a` / `f7e5e845d21e3a38ec5dc5ec04228b763acd9c5b` |

The source has445 Rules:415 converted automated Assessments,27 manual-only
Rules excluded, and3 automated Rules without converted content. Those three
are accounted for, not invented or scored as native Assessments. The published
RHEL9 namespace has no manual Assessment YAML to score. Applicability catalogs,
Rule selections, Profiles, manual alternatives and blocked-source records are
outside replacement edits and remain untouched. Historical proof/program
identities are copied as **retained evidence**, not recalculated acceptance.

For every converted Assessment, the audit verifies its original Rule hash and
every referenced OVAL dependency hash against the original pinned ZIP. The
complete [inventory](inventory.json) retains YAML hashes, source bindings,
dependency hashes, historical proof labels and the score breakdown. Each deep
review includes a `source.json` with the original OVAL node identities, DISA and
NIWC check text and exact source/Rule hashes. The ten DISA/NIWC manual check texts
are identical after whitespace normalization; no fuzzy comparison was used.

## Metric and threshold refinement

Version1 is an **authored logical-structure proxy**, not runtime cost or a proof
of semantic equivalence. It counts all authored Tests/Variables, including
maintainability burden; it does not claim a cache or scanner execution plan.

```text
score = T + B + max(D-1,0) + 2V + F + max(L-1,0)
        + 2S + 2Q + 2X + R + O
```

| Term | Definition |
| --- | --- |
| T | Number of Tests |
| B, D | Boolean operator nodes and maximum Boolean depth in `evaluate` |
| V | Variable declarations |
| F, L | Function/concat nodes and longest Variable/function reference chain |
| S, Q | Set operations and filter entries |
| X | Explicit Test-reference edges plus producer/consumer coupling through a Variable collection; labeled edges are retained, not asserted execution ordering |
| R | Extra references to identical collection selectors, excluding title metadata; potential repetition, not a claim that cached collections execute twice |
| O | Distinct comparison, cardinality, Boolean, function, set/filter, traversal and capability operation tokens |

Selectors are compared structurally after dropping presentation titles. Shared
Object references resolve before collection identity comparison. Variable chains
are followed transitively; cycles fail. Operator values such as regex contents
are preserved but not assigned arbitrary difficulty weights. Operation tokens
are syntax-level categories, not a claim that every regex or typed comparator
has identical semantic complexity. A simple presence Test scores4. Regrouping
the same Item quantifier does not manufacture a reduction.

**Shell cost guard:** external utilities do real work. The metric does not make
their hidden work disappear. Command stages, enumeration, privilege/output
contracts and retained semantic obligations are reviewed separately. Any
removed required condition invalidates the proposed reduction as an eligible
simplification. Thus the table below reports *apparent* structural reductions;
the estimated qualifying production reduction is **0%**, with0 replacements.

Initial score≥6 selected371/415 (89.4%), too broad to prioritize. A preliminary
nearest-rank80th percentile of13 included115 cases with boundary ties. Refining
to the highest `ceil(0.20 ×415) =83` scores gives a cutoff of**14**, exactly83
cases. All415 remain in the ledger; nothing was dropped to hide complexity.
Of the83, ten were deeply reviewed;46 others have set/filter/discovery burdens
and27 retain native or multicondition contracts without a bounded utility
substitute. These73 are conservative structural screens, not completed runtime
equivalence investigations. The remaining332 are below the refined threshold.

## Ten strongest review avenues and YAML pairs

Rank favors a bounded, readable evidence collector rather than raw score alone.
The five mount cases are the closest bounded collector avenues, but replacing
their file/Variable portion saves only40.91% overall and changes parser/status
behavior. Replacing the already simple `linux.partition` Test adds no justified
benefit. Every pair preserves exact original YAML bytes; proposed copies use
distinct audit IDs and current explicit Item/field requirements.

| Rank | Review case | Before → after | Apparent saving | Verdict / YAML pair |
| --- | --- | --- | --- | --- |
| 1 | `/var/log` nodev |22 →13|40.91%|Reject; [original](case-01/original.yaml), [sketch](case-01/proposed-UNAPPROVED.yaml) |
| 2 | `/tmp` nodev |22 →13|40.91%|Reject; [original](case-02/original.yaml), [sketch](case-02/proposed-UNAPPROVED.yaml) |
| 3 | `/var/log` noexec |22 →13|40.91%|Reject; [original](case-03/original.yaml), [sketch](case-03/proposed-UNAPPROVED.yaml) |
| 4 | `/var/log` nosuid |22 →13|40.91%|Reject; [original](case-04/original.yaml), [sketch](case-04/proposed-UNAPPROVED.yaml) |
| 5 | `/var/log/audit` nodev |22 →13|40.91%|Reject; [original](case-05/original.yaml), [sketch](case-05/proposed-UNAPPROVED.yaml) |
| 6 | At least two DNS name servers |30 →18|40.00%|Reject; [original](case-06/original.yaml), [sketch](case-06/proposed-UNAPPROVED.yaml) |
| 7 | FIPS systemwide policy |23 →8|65.22%|Reject; [original](case-07/original.yaml), [sketch](case-07/proposed-UNAPPROVED.yaml) |
| 8 | Crypto-policy backend overrides |21 →7|66.67%|Reject; [original](case-08/original.yaml), [sketch](case-08/proposed-UNAPPROVED.yaml) |
| 9 | AIDE installed and working DB |23 →8|65.22%|Reject; [original](case-09/original.yaml), [sketch](case-09/proposed-UNAPPROVED.yaml) |
| 10 | Extended-attribute audit syscalls |64 →8|87.50%|Reject enumeration/lost obligations; [original](case-10/original.yaml), [sketch](case-10/proposed-UNAPPROVED.yaml) |

The [ranked ledger](candidates.json) gives commands, source Rules, operation
breakdowns, assumptions, reason codes, hashes and remaining proof requirements
for each case. These are the strongest avenues examined, not ten passing
replacement candidates. None is recommended for implementation.

## Semantic comparison and evidence

**Mount cases:** source checks both live `linux.partition` options and the first
regex-matching six-column fstab entry, then splits its literal option capture.
The sketch retains live collection and uses a target-bounded
`findmnt --fstab --first-only --mountpoint … --output OPTIONS`. First-only is
necessary for duplicate/conflicting entries. Real fixtures show libmount accepts
four-column entries the source pattern rejects, and missing entries become
nonzero command status. Mapping that status to error changes source absence;
mapping it to false can hide permission or parse failures. No wrapper repair is
approved. Regex bytes are used verbatim without extra unescaping; independent
PCRE and Python match results agree on these bounded fixtures.

**DNS:** source separately checks DNS use in nsswitch, entry existence and the
count of unique capture values. The sketch keeps DNS applicability but
`grep | sort -u | wc -l` counts full lines, accepts malformed prefixes and can
count spacing variants of the same captured server as distinct. `pipefail`
preserves a failure signal, but does not by itself preserve absence/error
classification. The command collects a count rather than emitting compliance;
it still fails semantic and70% gates. No locale or empty-output defaults are
silently accepted.

**FIPS:** `update-crypto-policies --show` is already one source Test. Keeping only
it drops minimum RSA size, acceptable hashes and negated weak-algorithm checks.
**Overrides:** `--check` validates utility-defined selected-policy consistency;
its relationship to eleven exact FIPS symlink targets and the NSS regular-file
condition is not established. Utility version/generated-policy data and the
meaning of every exit status would need verification. Neither shorter sketch
reaches70%, and neither is a faithful replacement.

**AIDE:** `rpm -q aide` replaces an already simple package capability while
dropping recursive config discovery and the configured working database check.
Recreating those checks in shell would violate the discovery and logic-hiding
criteria. **Audit syscalls:** `auditctl -l` enumerates rules and does not preserve
the24 architecture/UID/syscall/persistent-file obligations merely because one
output line names a syscall. A Bash/awk/sed evaluator would move the complexity
rather than remove it. Its87.5% structural saving is therefore ineligible.

[Witnesses](witnesses.json) contain seven named scenarios per case: positive,
negative, missing, malformed, duplicate, conflicting and permission-denied.
There are**42 executed bounded-file component fixtures** (five mount cases and
DNS) and**28 abstract omitted-obligation countermodels** for the other four.
Source scalar regex/capture/instance/split or unique-count expectations are
implemented separately from the command-result model and checked against GNU
grep PCRE where applicable. Permission-denied files are actually read under an
unprivileged UID; chmod under root is not counted as denial evidence.

Execution used Debian13, util-linux2.41.5, not pinned RHEL9. The mount runtime
condition and DNS-use condition are held true to isolate the changed component.
The abstract cases state literal independent conjunction outcomes and required
utility assumptions; they are **not executed or demonstrated realizable RHEL9
system counterexamples**. Full OVAL collector/native scanner differential runs
were unavailable. Empty stdout is never used as a substitute for not-collected
or unknown. RHEL9 utility/package versions, missing/multiple/malformed values,
all error/unknown/completeness propagation, context/namespace, Rule applicability,
manual exceptions and evidence preservation remain separate proof obligations.

[Structural validation](structural-validation.json) accepts all ten proposed
sketches at canonical7354a24c. This establishes only schema shape. No compiler or
scanner is invoked, and neither schema acceptance nor compilation would prove
equivalence. The exact official manual ZIP receipt is in
[disa-download.json](disa-download.json).

## Other rejected patterns

- **Simple systemd/sysctl/rpm checks:** native capabilities already express
  bounded typed collection. `systemctl show`, `sysctl -n` or `rpm -q` add shell
  output/exit contracts without a70% maintainability improvement.
- **Initialization files, library directories, user home modes:** discovery,
  recursion, Sets, ownership, masks and per-user populations are material.
  `find … -exec stat`, loops or recursive greps fail the scope criteria.
- **sudoers and SSH/rsyslog includes:** include traversal, explicit declarations,
  first/all-instance rules and conflicts cannot be replaced by a single effective
  `sshd -T`/utility value without context/default/evidence changes.
- **Audit-rule families:** multi-architecture, UID, ordering and persistent versus
  active rules need their explicit semantics. Grepping a keyword is inadequate.

Potential future native maintenance avenues are collection sharing and constant
expression folding, with their own source-faithfulness review. They are not
implemented or counted as shellcommand savings here.

## Summary and owner-review outcome

| Measure | Count |
| --- | ---: |
| Converted automated Assessments analyzed |415|
| Manual-only Rules excluded / automated without native content |27 /3|
| Initial score≥6 / final score≥14 complex cohort |371 /83|
| Deeply reviewed sketches |10|
| Other complex cases conservatively screened to keep native |73|
| Shortlist rejections / all-criteria promising recommendations |10 /0|
| Shortlist full scanner-equivalence proofs / still unproved |0 /10|
| Production changes / qualifying estimated reduction |0 /0%|

No implementation approval is requested for the rejected sketches. Owner review
may choose a separate policy-correction or native-maintenance investigation;
that would not retroactively prove these replacements equivalent.

## Reproduce without a corpus regeneration

Install this repository's declared dependencies. Supply the three exact ZIPs
above; download the manual directly from Cyber Exchange, not a mirror. Use new
output paths. The scripts hash-check inputs, read only RHEL9 authoring/records
from the library, and verify source dependency identities.

```sh
python scripts/review_rhel9_shellcommands.py --archive /path/to/scap-ng-v04-normalized-library-review.zip --source /path/to/U_RHEL_9_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip --manual /path/to/U_RHEL_9_V2R9_STIG.zip --output /tmp/rhel9-review
python scripts/witness_rhel9_shellcommands.py --review /tmp/rhel9-review --output /tmp/rhel9-witnesses.json
python scripts/validate_rhel9_audit_sketches.py --schema-root /path/to/canonical-at-7354a24c --review /tmp/rhel9-review --output /tmp/rhel9-structure.json
PYTHONPATH=src python -m unittest discover -s tests -v
```

The standalone metric CLI `audit_rhel9_complexity.py` accepts `--archive`,
`--source`, `--output` for an unranked complete inventory. Fixture runs require
GNU grep with PCRE, bash and findmnt; version/platform observations are retained.
Unit tests require no corpus downloads or private source. The normal portable
CI retains its own existing exact schema/input pins. No workflow, production
package, canonical schema, compiler or original evidence is modified.

## Score distribution

Full exact frequencies follow; [inventory.json](inventory.json) contains every
per-Assessment component, selector-coupling edge and operation set.

| Score | Assessments |
| ---: | ---: |
|4|35|
|5|9|
|6|51|
|7|77|
|8|18|
|9|67|
|10|19|
|11|11|
|12|13|
|13|32|
|14|13|
|15|11|
|16|8|
|17|13|
|18|4|
|19|4|
|20|3|
|21|2|
|22|6|
|23|4|
|24|4|
|25|2|
|26|1|
|27|3|
|30|1|
|31|2|
|40|1|
|64|1|

Minimum 4, median 9, maximum 64.
