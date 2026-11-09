# Issue #28 integration preparation

Status: **unqualified draft; review required before full-65 qualification**.

## Foundation and donor policy

- Validation foundation: Tools PR #38 and standalone Variable support from PR #39 (`f97ff187460f52da78bd16f5009f7d182664812b`).
- Recovery donor: PR #33 functional runtime (`7106c6dd8093ee7b74ccfbad88ae1667a24c5516`), including the opt-in `count`, `split`, `substring`, `arithmetic`, identity, legacy-WMI, absence, and datatype candidates.
- Preservation donor: PR #42 (`8188c99`), including the source-only Nov. 5 packager and OCIL source graph extraction.
- Publication gate: PR #41 remains last; it is not integrated here.
- Frozen schema: SCAP-NG `f7e5e845d21e3a38ec5dc5ec04228b763acd9c5b`, family SHA-256 `63a61b3eb0ca95790721699f5e63b6f5a16b146660b9545a437519b508351db5`.

The runtime is one converter. PR #33's `manual04.py` was not carried into this branch: PR #42's richer source-backed OCIL adapter is the single manual representation. The #38 JSON/YAML serialization round-trip and provenance gates remain in `direct04.py`; PR #42's gate-removing facade was not adopted.

## Regression correction

PR #42's 11 parity failures were one default metadata regression plus one assertion cascade. The correction keeps the historical default `trace.scope`, `coverage.scope`, and coverage shape byte-compatible; recovery metadata is emitted only for explicit recovery modes. Identity-census behavior already present in the frozen default is retained; collision disambiguation and legacy-WMI lowering remain recovery-gated.

## Test evidence

With the VM-local source ZIP directory, detached frozen schema worktree, official OVAL checkout, and a temporary uncommitted source-fixture symlink (not part of this branch):

- PR #42 preservation branch after the correction: **52 tests, OK, zero skips** with the complete available fixture set.
- Integration branch full fixture-backed suite: **53 tests, OK, 1 expected skip**; default parity and current golden hashes passed.
- Integration branch inventory parity: passed in the same fixture run.
- Explicit metadata recovery tests: **3 tests, OK** (`native_recovery`, `recover_manual`, and default-shape assertions).
- Conversion validation and copied-runtime provenance tests passed after the reconciled source hashes were recorded.
- The remaining standalone OVAL Variable test is **an expected skip only**: its four-file public self-assertion corpus is not present in the VM. No skip was converted into a pass or hidden.

Explicit recovery probes on the Windows Server 2025 fixture were also kept separate from default parity:

- `native_recovery=True`: 259 converted, 32 blocked. The one `substring` candidate still blocks at the frozen-schema semantic gate; its generated function envelope is retained only in diagnostics. This is expected and is not a recovered/proved Rule.
- `recover_manual=True`: 247 automated, 30 manual, 14 blocked. OVAL remained the default for Rules with both checks, and OCIL-only Rules used the single source-backed manual adapter.

The PR #33 function visitor is therefore present as an opt-in candidate, but the frozen 0.4 schema rejects the candidate function envelope. The schema PR #27 candidate remains a review dependency and was not adopted.

No full-65 qualification, independent OVAL equivalence proof, compiler execution, or scanner execution is claimed.

## Next integration checks

1. Review this branch and the donor file-level diff.
2. Run explicit recovery deltas on a candidate schema only after the owner approves the schema pin.
3. Exercise the Nov. 5 packager against VM inputs, verifying source ZIP/Rule preservation and repeatability.
4. Run full-65 qualification only after review; keep structural draft, compiled, independently proved, and scanner statuses separate.
