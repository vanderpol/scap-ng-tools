# Issue #47 results

## Scope and immutable inputs

This work audits the active SCAP-NG 0.4.0 Variable functions and compares the
already-published `applicability.8` and `count.1` candidates. Neither archive
was regenerated or modified. The canonical 0.4.0 schema bytes were not
changed.

- Source commit: `8c8e5dff860af6b1290ee9273a282db24278f8d5`
- Schema commit: `8f8e219e4fb2db8b37a6d0e1ca418e8a392c38e3`
- Schema family SHA-256: `910beeebfb90a63c773615907289a0e4b93095ee41cd1ad41b33652363900c74`
- applicability.8 SHA-256: `e164ba54ac99ed1ebc6d205205deedea311ad92abd3d83739073eb0751ae4125`
- count.1 SHA-256: `5e34519ee38189d8a104770fc9f1e944b7f3681edf8a76636d931026a8b02571`

## Function matrix and regression

The machine-readable and Markdown reports are in
`docs/evidence/issue47/function-regression/`.

- Source inventory: 47 `count` occurrences in 37 Rules (the full function
  occurrence matrix is in the companion report).
- Active native functions: `concat`, `regex_capture`, `unique`, recursive
  `count`, and `merge`.
- Exact delta: **55** Rule instances changed `converted → blocked` between the
  two candidate ledgers.
- **50** contain an inactive generic `function` envelope emitted by the old
  recovery path; **5** are unrelated datatype/possible-restriction blockers.
- **0** regressions are count-bearing. Count.1 has **32 converted** and **5
  blocked** count-bearing Rules.

## Converter correction

Native recovery now fails closed for source `arithmetic`, `split`, `substring`,
`begin`, and `end`, and for variadic `unique`/`merge`, rather than producing an
inactive generic function envelope. Recursive single-operand count continues
to emit only `{count: expression}`. Existing active forms remain unchanged.

The correction does not claim that unsupported source functions are recovered;
their exact blockers remain in the candidate ledger and report. The five
unrelated Rule blockers remain open.

## Qualification and merge readiness

Focused tests cover nested count, duplicates, empty populations, missing
Variables, integer typing, incomplete/error/unknown/not-evaluated propagation,
and fail-closed inactive/variadic forms. The focused suite passed (56 tests
including the existing semantic and provenance tests). Full corpus generation
was intentionally not run per Issue #47 scope; a post-review full candidate
regeneration and independent archive qualification remain required.

**Recommendation:** the converter correction and audit evidence are ready for
review in draft PR #46. Do not promote a new archive or mark runtime/scanner
equivalence until the full corpus is regenerated and separately qualified.
