# Issue14: explicit binary32 recovery — 2026-11-03

Owner approval: **“Yes I approve”**, on 2026-11-03, approving the coordinated
contract work recommended in the [ten-case decision packet](ISSUE14-FLOAT-DECISION.md).
The original PR18 evidence remains immutable/reproducible under the preceding
default profile. This successor adds an **explicit opt-in** recovery path;
ordinary recovery and the frozen18-file strict converter keep their admission.
These are current-contract native DRAFTs, not source/scanner equivalence proofs.

## Source-faithful change

All ten original signed-source cases are inventoried in
[the exact pins](../tests/fixtures/issue14-float-pins.json) and
[original closure ledger](evidence/issue14-floats/investigation.json).
Their archives, datatypes, original lexical values (`10.0` nine times, `0` once),
`greater than or equal` operator, regex captures, Test/State/Set/Variable graph,
Item and field quantifiers, OCIL manual text and publisher defaults are retained.

The new recovery Visitor converts only scalar float State fields and the six
OVAL float comparison operations. It emits the existing `float_*` predicate,
never a generic integer/string comparison. It rejects Variables, record/selector
contexts, unknown attributes, comparator-bearing absence, unsupported operations,
invalid numerals and nonfinite expected values, including finite source decimals
that overflow binary32. Every admitted predicate carries source attributes,
original lexical text/node digest, resulting binary32 bits and contract ID/hash
in conversion provenance. No fallback command, cast-to-integer or cardinality
normalization is added. All ten real manual Assessments match their PR18 hashes.

Source decimal conversion uses exact integer ratios and nearest-even rounding
directly to IEEE754 binary32. A binary64 intermediate fails for a decimal just
above a binary32 midpoint. Subnormal/underflow, signed zero, overflow and malformed
lexical values have explicit behavior in the
[coordinated canonical contract](https://github.com/vanderpol/scap-ng/blob/da4c48dfc60dc96a46e7b85425f70fb8f301a0b1/docs/ISSUE12-BINARY32-REVIEW.md).
Expected native numbers must already be finite canonical binary32 values;
source `1.2` becomes numeric `1.2000000476837158` with provenance. Unqualified
native binary64 `1.2` is rejected by this profile. No nonfinite JSON number,
new Result shape, source float Variable or float arithmetic is activated.
Observed nonfinite encodings are internal comparison states; original text and
existing error/unknown/incomplete/collection propagation remain required.

## Exact before/after counts

| Scope | PR18 default profile | Explicit binary32 profile |
| --- | --- | --- |
| Ten original float cases | 10 blocked | **10 automated drafts / 0 blocked** |
| Original manual Assessments in those cases | 10 | **10 unchanged** |
| Re-run remaining48 candidate ledger | 3 drafts / 45 blocked | **13 drafts / 35 blocked** |
| Selected143 roll-up | 78 automated / 20 manual / 45 blocked | **88 automated / 20 manual / 35 blocked** |
| Historical422 automation-blocker backlog | 381 remaining | **371 remaining** |

The selected143 roll-up combines these ten changed rows with retained earlier
pilot receipts; it is not a new full143/65-Benchmark publication or proof pass.
The fresh48 ledger reruns all those candidates. Earlier98 complete Rule
projections/78 programs/214 Tests become a cumulative108/88/233 by adding ten
Rules/programs and19 Tests; the new native qualification covers only the ten
float Rules. No historical4258 proofs are rewritten or upgraded. Other8749
original Rules stay outside this qualified selected scope.

[Recovery ledger](evidence/issue14-binary32/recovery.json) records every before/
after status, original identities, manual hash, source warning and proof flag.
[Fresh48 classification](evidence/issue14-binary32/remaining48.json) preserves
the remaining blocker diagnostics. Both original investigation ledgers are
retained. `compiled`/independent-source/scanner flags stay false in conversion
output; native compilation has a separate receipt at its actual evidence layer.

## Contract, compatibility and qualification

All143 schema JSON bytes,100 mappings, frozen18-file runtime, four pinned
semantic-port modules, generated semantic pack,535 strict golden Rules and
old fixtures/proofs remain unchanged. A separate validation overlay enforces
canonical finite typed-float expected operands. The new comparison helper and
predicate inventory are shared with the coordinated native implementation;
the independent package reader uses its own traversal and numeric checks.

Affected native programs use `native-assessment-program/0.4`, with exact contract
ID/hash and sorted predicate operator/path/hash inventory. The reader rejects
missing, forged or downgraded metadata and changed program operands. Input
presence, existing `value_match`, approved function inventories and opaque literal
records retain their contracts. Programs without self-describing float operators
keep their old formats/bytes. Historical float programs require their pinned
pre-contract compiler/consumer or explicit recompilation, avoiding a silent
precision change. Legacy0.3 and manual Assessments are unaffected.

Local portable tests: **77 pass, zero skips**, including the ten original cases,
strict/default rejection, all six comparisons, direct-rounding ties, malformed
values, canonical/noncanonical operands, quantifiers and manual preservation.
Canonical18 tests include an independent exact-rational justification of19 fixed
vectors. An additional independent native C experiment checks57 casts and342
comparisons against those vectors. This is numerical conformance evidence only,
not an OVAL evaluator or complete Rule outcome proof.

The coordinated native check compiles the actual complete recovered source
groups and checks their schema/graph/packages, independent native source/program
identity and negative mutations. See [native qualification](evidence/issue14-binary32/native-qualification.json)
and [local validation receipt](evidence/issue14-binary32/local-validation.json).
Local maintained native/schema and six-Benchmark legacy regressions are recorded
with exact commands, counts and limitations on the coordinated PRs. No artifact
quota retry, six-transfer workflow change, release preparation, Editor PR36
change, scanner-equivalence or release-readiness claim is included.

CI preserves the exact old canonical checkout used by the235-resource Editor
metadata proof, and adds a separately pinned binary32 contract checkout. It does
not relabel those old metadata resources as a new editor profile. Portable CI
still performs all original checks plus the new focused tests, without uploads.

## Reproduce the explicit profile

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python scripts/recover_float_cases.py \
  --schema-root /path/to/canonical-da4c48dfc60dc96a46e7b85425f70fb8f301a0b1 \
  --source-root /path/to/pinned/Archive/2026_Q3 --output /tmp/fresh-binary32-recovery
```

For another focused Rule selection, `scripts/recover_benchmark.py` takes
`--binary32-comparisons` with the same exact contract sidecar requirement.
`scripts/qualify_binary32_recovery.py` runs the optional pinned external native
toolchain in a fresh process. `scripts/check_binary32_native_oracle.py` runs the
independent C numerical experiment when a compatible C compiler is available.
The original `investigate_float_comparisons.py` remains the PR18 default-profile
investigation; its ten blocked cases are not silently relabelled as current
profile output. All implementation PRs remain draft for coordinated review.
