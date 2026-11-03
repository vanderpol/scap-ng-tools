# Issue14 coordinated function amendment — 2026-11-03

Owner [approved the separate three-function scope](https://github.com/vanderpol/scap-ng-tools/issues/14#issuecomment-6592397246).
The initial Firewall/38-recovery milestone stays immutable at
`72f7ec2317c409362393c9c0d74b19d081b38f05` / PR15. This branch is stacked on
that checkpoint. It adds only arithmetic, substring and split to the recovery
visitor and portable semantic gate; the frozen strict runtime remains unchanged.

The [canonical review packet](https://github.com/vanderpol/scap-ng/blob/246a8d37cc54875386768a7d76b60a6f9c01d013/docs/ISSUE10-FUNCTION-REVIEW.md)
records the syntax, source examples, domains, status/multiplicity boundaries,
compatibility, rejected alternatives and dated owner direction. It is a review
candidate, not subsequent human acceptance or a runtime evaluator.

## Exact coordinated identities

- Canonical schema PR11: `246a8d37cc54875386768a7d76b60a6f9c01d013`.
- Schema family: `f19246c60814f7768a5564cd335675b4c2c6ae721ebd6a464ee9a6f17185e0a3`, 143 JSON / 34 roots / 244 refs / 100 mappings.
- Semantic pack: `3369ee0501b8296d9e214fadbe31538fdfdf02d9e736dbde49aa7085a6efffa1`; only its schema fingerprint changes. All 52 capability contracts and eight behavior declarations are identical.
- Offline metadata resource identity: `fa1398c16a6fcc91b1acf9a37bd70c56d4d6de7ec1233ce407b438a4b475ea6a`.
- Metadata manifest: `414c557ad1a0f3b2a93f667cfe4a63d2b1d7615505368bc51fab57049748781f`; exactly variable-expression.schema.json changes among 235 resources. All capability resources/mappings remain identical.
- Optional external compiler qualifier: `4fccf51d96a529583a18005776e5cb21ea459885`. It is not a public runtime, package or CI dependency.
- NIWC source: `8c8e5dff860af6b1290ee9273a282db24278f8d5`; official OVAL 5.12.3: `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`.

Prior pins remain recorded in constants and the earlier commits; old artifacts
and proof hashes are not rewritten. The legacy 0.3 validator is unchanged.

## Focused eleven-case result

[Exact Rule/ZIP ledger](evidence/issue14-functions/focused-ledger.json) and
[package receipts](evidence/issue14-functions/qualification.json) preserve the
before/after boundary. Two Solaris Rules recover: x86 SV-216066 and SPARC
SV-216301. Each compiles and independently consumes against external native
authoring: five documents, one program, eight Tests, with one real manual choice.
Source default selection is preserved. Original OVAL equivalence and scanner
execution remain unproved.

Nine Rules remain blocked: five by unsupported original WMI Objects, three by
unqualified all_exist population semantics, and one by direct Input function
composition. The arithmetic source declarations also request string results;
subgraph tests explicitly reject silently casting the new numeric function result.
No Rule is admitted by diagnostic-only lowering. The full historical automated
backlog changes from 384 to 382: 40 recovered since the original 422, 46 attempted
blockers plus 336 held cases. The selected 143-Rule accounting becomes 77
automated drafts / 20 manual-only / 46 blocked. Combined package receipts cover
97 complete Rule projections, 77 programs and 213 Tests; 143 manual methods
remain retained, including standalone methods beside blocked Rules. The other
8749 Rules are not claimed current-schema tested.

A polymorphic collected field advertises possible domains. A string function's
explicit signature constrains its projection, consistent with the existing type
constraint model. No strings/booleans/records are cast into numeric arguments,
no direct Input expression is added, and runtime incompatible data remain errors.
The compiler serializes ASTs and new program/0.3 function inventories without
executing values; old function-free 0.1/0.2 program bytes remain unchanged.

## Reproduction and checks

```sh
PYTHONPATH=src python scripts/probe_function_cases.py \
  --schema-root /path/to/exact-canonical-checkout \
  --source-root /path/to/pinned/Archive/2026_Q3 --output /tmp/function-replay
```

The script attempts only the eleven pinned Rules and refuses existing output.
The optional compiler qualification script accepts an explicit exact compiler
checkout and compares native source/package identity; it does not prove original
OVAL semantics. No new full65 library is built or published.

Tests add three real signed-source subgraphs (Amazon arithmetic, Windows
substring, Solaris split), complete option/arity/domain negatives, direct Input
rejection, collection/empty/duplicate preservation, nested legacy forms, opaque
record literals and inventory paths. The strict 535-Rule document/trace/coverage
and admission goldens remain unchanged. Hosted CI adds only the one exact Solaris
ZIP needed for the third source operation; no gate or skip is weakened.
The first local full portable run had one stale source-hash allowlist assertion;
the explicit new hash was corrected while preserving the previous floor, and
its three provenance tests pass. Final exact-commit hosted receipts are recorded
on the PR when complete.

Compiler maintained 43-script/311-test rerun passes after restoring historical
program-only mutant setup. Schema CI at 246a8d3 passes all 16 tests and generated
documentation. Metadata inverse/export tests pass; exact editor pin integration
is tracked separately in scap-ng-vscode Issue27, without office UI18 changes.
