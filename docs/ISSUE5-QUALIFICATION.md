# Issue #5 portable 0.4 admission qualification

This document records the post-merge qualification of the portable automatic
benchmark-admission work from Tools PR #5. It does **not** reopen or replace
that merge, alter the published corpus, or grant proof/scanner authority.
The merge commit is `9c9cbaf024c3b46a4bc6c9886edd80c0d83fb68d`.

## Qualification command

The read-only harness keeps native documents in memory and writes only its
machine-readable receipt. It requires an explicit flat 0.4 schema checkout and
the four signed fixture ZIPs:

```sh
PYTHONPATH=src python scripts/qualify_v04_portable_admission.py \
  --schema-root /path/to/scap-ng \
  --fixture-root /path/to/Archive/2026_Q3 \
  --report /tmp/issue5-qualification.json
```

It refuses to overwrite the report, verifies each source ZIP before parsing,
checks both inventory and automatic-admission trace/coverage digests, and
rejects any promotion to source-proved or scanner-evaluated status. It does
not emit an Assessment corpus.

## Results against the pinned acceptance fixtures

| Source | Rules | Admitted | Blocked | Native documents |
| --- | ---: | ---: | ---: | ---: |
| Windows Server 2025 | 291 | 247 | 44 | 496 |
| Active Directory Domain | 36 | 15 | 21 | 32 |
| Amazon Linux 2023 | 187 | 118 | 69 | 238 |
| Windows Defender Firewall | 21 | 0 | 21 | 0 |
| **Total** | **535** | **380** | **155** | **766** |

The run used the exact schema family digest
`63a61b3eb0ca95790721699f5e63b6f5a16b146660b9545a437519b508351db5`
and schema commit `f7e5e845d21e3a38ec5dc5ec04228b763acd9c5b`. The source ZIP
hashes, per-fixture inventory receipts, automatic coverage receipts, source
traces, and native-document hashes are asserted by the harness and the
existing integration tests. A local run on 2026-11-12 took 23.664962 seconds
(command execution only; model/analysis time is not included).

The deterministic semantic pack remains the pinned 52-capability pack with
SHA-256
`b78c4db59da4cb2bad4f783e9562a5df9060de1a0e60f29ff4afceef8443ca70`.
The portable package contains no source checkout, historical schema tree, or
OVAL XSD runtime dependency. The build-only pack generator is kept separate
from the installed converter.

## Requirement disposition

| Requirement | Result | Evidence |
| --- | --- | --- |
| Explicit schema root and source ZIP SHA-256 | **PASS** | `direct04.py`, harness, schema snapshot tests |
| Native JSON/YAML, coverage and source trace | **PASS** | `direct04.py`, benchmark conversion tests |
| Explicit `CONVERTED_UNVERIFIED` scope | **PASS** | `conversion-scope.json`, negative proof-mode test |
| Original strict semantic gates and optional validator callback | **PASS** | `_v04_semantic/`, `convert_benchmark(... validate_document=...)` |
| 52-capability deterministic semantic pack | **PASS** | `generate_v04_semantic_pack.py`, provenance tests, flat-schema CI |
| Installed runtime independent of research checkout/XSDs | **PASS** | package-owned runtime and provenance allowlist tests |
| Original CLI acceptance and negative boundaries | **PASS** | focused and 535-Rule regression tests |
| Broader legacy/integration qualification | **PASS** | four-fixture inventory plus automatic admission: 535 Rules, 766 native docs |
| Fixture/XSD licensing and redistribution review | **PARTIAL** | see `THIRD-PARTY-FIXTURE-ACQUISITION.md` |
| External VS Code editor profile repin | **PENDING** | Tools exporter is pinned and qualified; editor repository is separate |

The last two items are intentionally not represented as completed by this
Tools change. The NIWC fixture license is recorded; the OVAL repository does
not expose an SPDX license or license file at the pinned checkout and needs an
owner/legal decision before redistribution or vendoring. No third-party source
is bundled by this package. The VS Code profile must be changed in its own
coordinated review.

## Non-claims and preservation

- `--draft`, `--compile`, `--verify`, independent proof, manual/OCIL
  conversion, and scanner execution remain unchanged and fail closed where
  unmigrated.
- `CONVERTED_UNVERIFIED` is authoring/structural admission, not scanner or
  runtime equivalence.
- The historical 535-Rule baseline and all four source ZIP identities remain
  unchanged. No generated corpus or published archive is modified here.
