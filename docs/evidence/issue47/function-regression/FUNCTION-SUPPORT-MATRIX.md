# SCAP-NG 0.4 Variable-function support and Issue #47 regression audit

Read-only comparison of the immutable `applicability.8` and `count.1` candidate ledgers; no corpus was regenerated.

## Result

- **55 exact Rule regressions:** `converted → blocked`.
- Classification: **50** inactive-envelope outputs and **5** unrelated datatype/schema blockers.
- Count-bearing regressions: **0** (none expected). The count.1 inventory has 32 converted and 5 blocked count-bearing Rules.
- Runtime/scanner equivalence is **not** claimed.

## Pins and immutable inputs

- applicability.8 SHA-256: `e164ba54ac99ed1ebc6d205205deedea311ad92abd3d83739073eb0751ae4125`
- count.1 SHA-256: `5e34519ee38189d8a104770fc9f1e944b7f3681edf8a76636d931026a8b02571`
- Source: `8c8e5dff860af6b1290ee9273a282db24278f8d5`
- Schema: `8f8e219e4fb2db8b37a6d0e1ca418e8a392c38e3` (SHA-256 `910beeebfb90a63c773615907289a0e4b93095ee41cd1ad41b33652363900c74`)
- count.1 generator: `0822dd7e4a3b8a7e5656f98322805d28447f1d7c`

## Function-support matrix

| Function | Active native 0.4 | Source uses | Source Rule IDs | count.1 Rule instances (overlapping) | Converter contract |
|---|---:|---:|---:|---|---|
| `arithmetic` | no | 9 | 4 | blocked=4 | fail_closed; inactive function envelope is forbidden |
| `concat` | yes | 750 | 299 | blocked=60, converted=251, intentionally_excluded=16, manual_only=1 | active_native_shape |
| `count` | yes | 47 | 37 | blocked=5, converted=32 | active_native_structural; 32 count-bearing Rules converted |
| `end` | no | 3 | 2 | blocked=2 | fail_closed; inactive function envelope is forbidden |
| `merge` | yes | 106 | 61 | blocked=14, converted=53 | active_native_shape; multi-component source form is unsupported |
| `regex_capture` | yes | 320 | 128 | blocked=16, converted=105, intentionally_excluded=6 | active_native_shape |
| `split` | no | 29 | 23 | blocked=23 | fail_closed; inactive function envelope is forbidden |
| `substring` | no | 21 | 8 | blocked=8 | fail_closed; inactive function envelope is forbidden |
| `unique` | yes | 63 | 87 | blocked=31, converted=86 | active_native_shape; multi-component source form is unsupported |

Active grammar is `concat`, `regex_capture`, `unique`, recursive `count`, and `merge`; the historical generic `function` envelope is not active 0.4 syntax.


