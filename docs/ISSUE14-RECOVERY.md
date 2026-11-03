# Issue14 — Firewall and blocked-Assessment recovery, 2026-11-03

Review candidate under [Issue14](https://github.com/vanderpol/scap-ng-tools/issues/14),
using the owner's isolated-head authorization. Current schema-valid DRAFT and
package consistency are distinct from original-source semantic proof or scanner
execution. No new qualified65 library is published or integrated into the editor.

## Pins and source preservation

- Canonical schema `d4e477998cda438a1e53a7c3c84123ec92e5ba1f` (PR9).
- Tools base `1c8aa287808f3ad0aa3d5e8aa610d800e8862c22` (PR13).
- Optional external qualification compiler `b34db42f40d801662fb08ab6c64be36dad03327b`.
- NIWC original65 source manifest `8c8e5dff860af6b1290ee9273a282db24278f8d5`;
  use `Archive/2026_Q3/`, never moving Current.
- Firewall V2R3 ZIP SHA256
  `d16c868152e14bab0a1e2ecdfa6ec889972e068625d4d20d4ac3f861ff2009ca`.
- Complete schema-family SHA256
  `04074a04cf3e5378fcc99e4f7780ff2e10f032e400751c35cea960aa0c42d971`.
- Historical review ZIP SHA256
  `a01ea589501bf8a53e5df68e50ca9478f19543d2bd3844546667fde743c28d8c`.
  Its old grammar, source, programs and4258 proof receipts remain immutable;
  none of those old proofs is promoted to a current proof.

The fresh65-source inventory matches all original ZIP and Rule hashes against
the historical ledger, accounting for8892 Rules. Only bounded selected batches
are converted. Complete originals, source check selectors, OCIL nodes/answer
mappings/default-answer metadata, XCCDF Value/export context, profiles, source
platform references and component hashes remain in the source trace. The source
ZIP is read without mutation. Native platform/CPE execution and full
policy/remediation equivalence remain **unqualified**; source preservation does
not establish those executable contracts. Every output declares that boundary.

## Firewall before and after

| Lane | Source Rules | Automated | Manual | Blocked | Qualification |
| --- | ---: | ---: | ---: | ---: | --- |
| Historical strict public lane |21|0|0|21|Frozen automated-only goldens|
| Historical focused draft |21|20|0 native alternatives|1|Old authoring-valid draft only|
| Fresh pinned draft replay before fixes |21|1|0|20|2 Parameter-name aliases and17 Test-name collisions, plus manual-only selection|
| Current recovery |21|20|21 Assessments|0|Current schema/semantic gates and package checks|

SV-242009 remains manual-only with its source manual default. All20 automated
Rules retain their real OCIL alternative and their source automated default.
Manual methods preserve original question/procedure text and explicit choice
mapping (Finding→false, Not a Finding→true, Not Applicable→not_applicable,
Not Reviewed→not_evaluated). Those mappings come from source `when_choice` results;
no answer or automatic outcome is generated. Source default answers are recorded
but never applied as supplied responses. Compound/unrecognized/conflicting OCIL
workflows reject; no general OCIL evaluator is implied.

| Rule | Current status | Native choices | Compile/package | Independent source proof |
| --- | --- | --- | --- | --- |
| SV-241989 | AUTOMATED_DRAFT | automated + manual | PASS | NOT RUN |
| SV-241990 | AUTOMATED_DRAFT | automated + manual | PASS | NOT RUN |
| SV-241991 | AUTOMATED_DRAFT | automated + manual | PASS | NOT RUN |
| SV-241992 | AUTOMATED_DRAFT | automated + manual | PASS | NOT RUN |
| SV-241993 | AUTOMATED_DRAFT | automated + manual | PASS | NOT RUN |
| SV-241994 | AUTOMATED_DRAFT | automated + manual | PASS | NOT RUN |
| SV-241995 | AUTOMATED_DRAFT | automated + manual | PASS | NOT RUN |
| SV-241996 | AUTOMATED_DRAFT | automated + manual | PASS | NOT RUN |
| SV-241997 | AUTOMATED_DRAFT | automated + manual | PASS | NOT RUN |
| SV-241998 | AUTOMATED_DRAFT | automated + manual | PASS | NOT RUN |
| SV-241999 | AUTOMATED_DRAFT | automated + manual | PASS | NOT RUN |
| SV-242000 | AUTOMATED_DRAFT | automated + manual | PASS | NOT RUN |
| SV-242001 | AUTOMATED_DRAFT | automated + manual | PASS | NOT RUN |
| SV-242002 | AUTOMATED_DRAFT | automated + manual | PASS | NOT RUN |
| SV-242003 | AUTOMATED_DRAFT | automated + manual | PASS | NOT RUN |
| SV-242004 | AUTOMATED_DRAFT | automated + manual | PASS | NOT RUN |
| SV-242005 | AUTOMATED_DRAFT | automated + manual | PASS | NOT RUN |
| SV-242006 | AUTOMATED_DRAFT | automated + manual | PASS | NOT RUN |
| SV-242007 | AUTOMATED_DRAFT | automated + manual | PASS | NOT RUN |
| SV-242008 | AUTOMATED_DRAFT | automated + manual | PASS | NOT RUN |
| SV-242009 | MANUAL | manual | PASS | NOT RUN |

Publisher-default and controlled organization-resolved variants both pass native
compile, packaged verification and independent external-source comparison:
**64 documents /20 automated programs /109 Tests**. Manual choices produce no
programs. SV-241989 retains its source integer default1, original explicit Test
existence/satisfaction controls and compact grouped Item/Field requirements.
The organization option is an explicitly labelled policy derivative; it removes
publisher defaults rather than claiming the source delegates them. An omitted
authored discovery map is derived by the compatible compiler. An explicitly
controlled optional derivative compiles only under its positive presence guard;
its native metadata has both value/presence sites. This derivative is not an
original-source proof or scanner fixture.

Eight negative compiler cases reject: missing required/unknown binding,
missing Parameter, datatype/cardinality mismatch, dishonest map, wrong pointer
kind and unguarded optional consumption. Portable tests separately reject an
incompatible publisher default, unknown selector, incomplete/unknown OCIL answer
mapping and unsupported real Value constraints. See the machine
[Firewall ledger](evidence/issue14/firewall-ledger.json) and
[qualification receipts](evidence/issue14/qualification.json).

## Follow-on recovery and scoreboard

The smallest follow-up benchmark, Active Directory Domain V3R6, accounts for
36/36 Rules:17 automated drafts and19 manual-only Rules, with36 manual methods.
Its91-document package has17 programs/39 Tests. Strict admission was15; historical
focused draft was17. Native manual preservation is new in this lane.

The fresh read-only source inventory has7239 Rules with OVAL checks and1653
manual-only Rules (8892 total). All8892 have OCIL source. Overlapping source
obligations include426 external-Variable consumers,382 check-export Rules,
1777 all_exist Rules,367 function Rules,56 reference/selection diagnostics and
295 Rules outside the portable52-capability pack. These are **source patterns**,
not current admission failures, and do not add to a single denominator.

The preserved full65 ledger had6817 old compiled drafts, including4258 retained
proofs and2559 unproved drafts, plus1653 manual-only and422 automated blockers.
We matched every original Rule identity, held199 invalid/deprecated and137 SQL
extension cases, then attempted the remaining86 blockers with current gates.

**38 now recover;48 still block.** Four former “Value constraint” failures were
plain warning metadata. Warning text/category/language are preserved without
inventing Input constraints. Another34 Value operators exactly agree with every
actual OVAL consumer. Their existing native comparison predicates are retained;
no new operator, coerced value, inferred bound or language extension is introduced.
Two disagreements remain blocked. Two explicit string/equals var_ref defaults
are accepted as defaults; the affected Solaris Rules still block on dynamic
split functions, which the first error had hidden.

The38 recovered Rules compile and pass independent package consumption:
38 programs/49 Tests. Together, the selected143 current attempts account for
75 automated drafts,20 manual-only Rules and48 blocked Rules. **95 complete
Rule projections compile, with75 programs/197 Tests.** All143 native manual
methods survive;95 are bound choices and48 remain standalone beside blocked
Rule ledger records. The source default is never switched to hide missing
automation. A compiled projection still does not prove full original policy or
CPE equivalence.

Remaining historical automated backlog: **384 =48 attempted blockers +336 held**.
The48 include10 ordered-datatype cases,9 comparator-bearing absence cases,
11 dynamic function cases (arithmetic4/substring5/split2), and explicit source,
selector/type or capability mismatches. New functions and unsafe datatype or
absence reinterpretations are not implemented by this recovery.

[Machine scoreboard](evidence/issue14/scoreboard.json) separates all65 source
counts, immutable historical outcomes, current attempts, current qualification,
per-benchmark/root-cause rankings and remaining gaps. Current results cover143
Rules; the other8749 are not claimed current-schema validated or compiled.

## Implementation and tests

The recovery API/script is an explicit lane. Existing strict CLI `--all-rules`,
focused output, unsupported `--draft`/compile/proof modes and original535-Rule
strict source/document/trace/coverage goldens remain unchanged. Two audited
runtime files expose a visitor factory and bounded Input metadata/name hooks;
new recovery code supplies the adapters. The other13 runtime files, semantic
pack, generator helpers and schema/mapping bytes keep their pinned hashes.
Previous runtime hashes remain recorded in provenance tests and Git history.
Naming uses readable, bounded local source discriminators; collisions reject,
and no source ID is promoted to global semantic identity.

Local portable suite: **45 tests PASS, zero skips** using nine exact source ZIPs.
The existing535-Rule goldens and semantic-pack integrity checks pass. Added tests
exercise21/21 accounting, manual choices/defaults, original Test controls,
organization bindings, source pinning, naming, invalid selectors, real/false
constraints,34 operator-preserving admissions and two disagreements. Optional
external compiler qualification is recorded separately and is not a public
package/CI dependency. Hosted PR receipts identify the exact containing source.

## Reproduction

Install the public package dependencies and select the exact offline schema:

```sh
PYTHONPATH=src python scripts/recover_benchmark.py \
  --schema-root /path/to/pinned-scap-ng \
  --source /path/to/original-firewall.zip --sha256 d16c868152e14bab0a1e2ecdfa6ec889972e068625d4d20d4ac3f861ff2009ca \
  --output /path/to/new-firewall-draft
```

Use `--organization-parameters` only for the labelled controlled policy derivative;
`--rule SOURCE_ID` selects a bounded batch. Existing output is never overwritten.

```sh
PYTHONPATH=src python scripts/inventory_recovery_corpus.py \
  --schema-root /path/to/pinned-scap-ng --source-root /path/to/pinned-niwc \
  --source-commit 8c8e5dff860af6b1290ee9273a282db24278f8d5 --output /path/to/new-inventory.json
PYTHONPATH=src python scripts/summarize_recovery_inventory.py \
  --inventory /path/to/new-inventory.json --historical-review /path/to/original-review.zip \
  --historical-sha256 a01ea589501bf8a53e5df68e50ca9478f19543d2bd3844546667fde743c28d8c \
  --output /path/to/new-scoreboard.json
PYTHONPATH=src python scripts/probe_recovery_backlog.py \
  --schema-root /path/to/pinned-scap-ng --source-root /path/to/pinned-niwc \
  --scoreboard /path/to/new-scoreboard.json --output /path/to/new-bounded-probes
```

The optional `qualify_recovery_with_toolchain.py --help` documents explicit
compiler-root/commit, documents, ledger and new output inputs. `--derive-maps`
checks source omission and `--negatives` exercises the Firewall mutants. Add
`--current-ledger` and explicit `--current-overlay` qualification receipts to the
summarizer; duplicate attempts are never counted twice. `--backlog-summary`
adds actual recovery/remaining counts. No source/schema/tool is fetched at runtime.

## Further contract work

The active Decision29 Variable grammar is closed. The separate
`variable-function-expression.schema.json` explicitly says it is an inactive
candidate, not referenced by Assessment, and grants no runtime support. Enabling
arithmetic, substring or split would require a coordinated owner-reviewed native
contract/compiler/type/status/metadata amendment, not a converter-only bypass.
Other remaining cases need source correction or explicit adapters for their
actual semantics. The existing all_exist diagnostic lowering is held in this
lane rather than treating positive collected Items as proof of complete expected
population. No schema or scanner semantics are changed here. No full65 native
library, old proof rewrite, new release or editor task dependency is introduced.
