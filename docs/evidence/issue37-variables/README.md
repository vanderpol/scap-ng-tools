# Immutable standalone Variable handoff

Four complete original Definitions, **18 Tests**, ten Variable declarations. Producer code: `329332ad8d24f0ee4605733b7b90dce1c95dc500`. See [manifest.json](manifest.json) for exact source/schema revisions, actual CLI commands, byte counts and artifact SHA-256 values. Each source commit/path was checked against its original Git blob.

The sole production CLI generated each `assessment.json` / `assessment.yaml` pair; a separate `Draft202012Validator` over approved schema `6012ae2` validated the actual JSON, and independent YAML read-back matched it exactly. All outputs remain `CONVERTED_UNVERIFIED`. Whole criteria, original class, all Tests, named Variables and alias edges remain. No collected Items or compliance outcomes were fabricated.

[validation.json](validation.json) records the full **54-test, zero-skip** Tools run, exact environment/command and source hashes. The CI fixture uses `f7e5e84`; its frozen schema bytes equal approved `6012ae2`. Existing 535-Rule / 766-document native and trace goldens remain passing.

[review-validation.json](review-validation.json) records the subsequent **55-test, zero-skip** review run. Its added check verifies every committed handoff artifact's hash/size, schema and YAML equality, then joins its native document and source bindings to a fresh production conversion. The immutable handoff remains artifact commit `d326e9d025c81f0292eadfb3dbf86e768960219d`.

Native execution is a separate RI handoff. This pack does not establish Variable materialization, scanner equivalence, SCC qualification or execution of any original Test. See [source fidelity and holds](../../ISSUE37-STANDALONE.md). The source-Test expectations in RI PR #37 are external comparison evidence, never converter/evaluator input.

Original XML and frozen schemas are unchanged. [NOTICES.txt](NOTICES.txt) preserves public source terms and derivative attribution. Prior historical artifacts/proofs are retained and are not requalified by these files.
