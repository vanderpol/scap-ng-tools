# Agnostic Self-Assertion 46-Definition closure gate

Owner decision: [scap-ng-tools#59](https://github.com/vanderpol/scap-ng-tools/issues/59#issuecomment-6945179505). The original OVAL-Community source remains immutable; no source file is rewritten and the original source SHA is retained in every conversion receipt.

## Scope

- Original source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`.
- Exactly 46 original agnostic Definitions across 35 original XML files.
- Independently source-derived expected outcomes: **44 TRUE / 1 FALSE / 1 UNKNOWN**. A FALSE or UNKNOWN Definition can be a correct Self-Assertion.
- Baseline qualified: 39 TRUE + 1 expected UNKNOWN = 40/46 correct. Six remaining discrepancies in three XML files.
- Owner-accepted compatibility: 3 binary->boolean Variable declarations and 5 int->string *Variable declarations*. Integer input `var:100` in merge stays integer; merged output remains string.
- Scope is **source compatibility**, **not original malformed OVAL semantic equivalence** or general datatype coercion.
- The converter must still reject invalid literal values and mixed/ambiguous unapproved changes.

## Implementation

`native041_self_assertion_typing.py` is a SHA+path+source-commit-pinned **in-memory visitor overlay**. It clones exactly eight source Variable declarations, checks each old datatype, and provides a corrected clone only to the native converter visitor. Original XML/node indexes and original Git blob hashes are unchanged. Per-Variable original/normalized node SHA and resolved datatype are recorded as a source-compatibility disclosure in `source_type_normalizations`, alongside the normal source trace.

`expected-definitions.json` is the source-backed 46-row static manifest. No actual RI Test or Definition result was used to assign the expected outcomes. The IPv4/IPv6 conformance Definitions use their original criteria and accepted TRUE expectation despite titles that do not begin with "Evaluate to true".

`tools/check_agnostic_definition_gate.py` requires exactly one **executed** Result for every source Definition, with the exact pinned original XML SHA, source path, Definition ID and independent expected technical outcome. A not-executed, blocked or mismatching case fails. It does not execute the scanner and **does not provide execution proof by itself**.

## Exact rerun

Use matching checkout/worktrees (source, schema, converter and RI) rather than `main` or stale caches. Python 3, converter dependencies, Go 1.27.4, and a prebuilt RI binary are required.

```bash
# Inside the RI checkout, build ONCE, using the qualified Go 1.27.4 toolchain:
go build -o /tmp/ri-benchmark-agnostic ./cmd/ri-benchmark

# Use the patched Tools converter's scapng-convert-v04 entrypoint.
python3 tools/run_agnostic_definition_qualification.py \
  --source-root /path/to/SCAP-Self-Assertion/SCAP_1.4/OVAL_Test_Content \
  --schema-root /path/to/scap-ng/schema \
  --converter /path/to/patched/scapng-convert-v04 \
  --ri-root /path/to/scap-ng-ri \
  --ri-binary /tmp/ri-benchmark-agnostic \
  --expectations /path/to/scap-ng-tools/docs/qualification/agnostic-self-assertion/expected-definitions.json \
  --checker /path/to/scap-ng-tools/tools/check_agnostic_definition_gate.py \
  --out /path/to/new-private-agnostic-run
```

The runner is in the **RI repository** (separate short PR). It verifies the original Git HEAD, refuses source/hash drift, converts complete Definitions (not selected Tests), preserves the native Evaluate tree including NOT, runs through RI `ri-benchmark`, and emits:
- `definition-results.csv`: the fresh 46-row actual-outcome ledger;
- `definition-gate.json`: source-pinned 46/46 comparison;
- `qualification-pins.json`: actual RI SHA, original source commit, RI binary SHA, ledger/expectations hashes;
- `cases/NNN/`: one conversion trace and canonical Assessment Result per source Definition.

No original XML, generated Assessment or real Result outcome is changed to force a pass. Unknown, Error, and blocked outcomes remain visible.

## Acceptance and merge hold

1. Targeted Python tests and existing standalone converter regressions pass on the exact PR head.
2. All 46 original Definitions are converted/validated and executed on the pinned schema and RI.
3. The independent Definition gate reports **46/46 matching: 44 TRUE, 1 FALSE, 1 UNKNOWN**.
4. All three corrected-source files carry the exact source compatibility receipts.
5. No unrelated source pair changes behavior; no schema/runtime datatype special-case was added.
6. Publish original source SHA, converter/schema/RI SHAs, binary SHA and per-case privacy-safe receipts. Keep PRs draft until the actual gate is green.

If the gate is not 46/46, do not waive it. Inspect the failing source-linked Definition and fix only the reproduced converter or shared evaluator defect, then rerun all 46.
