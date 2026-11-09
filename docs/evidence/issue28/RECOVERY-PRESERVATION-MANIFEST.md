# Issue #28 recovery preservation manifest

**Qualification: `UNQUALIFIED_RECOVERY_ONLY`.** This PR preserves previously uncommitted converter code, tests, and evidence metadata. It does not claim schema, compiler, OVAL, scanner, or independent semantic qualification.

- Source worktree: `/home/u1239716047117002/Documents/scap-ng-vscode/.external/scap-ng-tools/.worktrees/issue28-variable-recovery`
- Source HEAD: `545580211384c55e80ed2b4b6589e2cfc23dc184`
- Recovery branch base: `545580211384c55e80ed2b4b6589e2cfc23dc184`

## Included

- `src/scap_ng_tools/converter/_v04_runtime/v04_direct_converter.py` — 86599 bytes — `b6d4df379adb350283229051cedaab2a46b26bdc63c3a3d5e65721b167e36cee`
- `src/scap_ng_tools/converter/_v04_runtime/v04_direct_scap_source.py` — 18284 bytes — `fb1bf16d2a1e24d729742c3e2a7b711b4a7926d7ed4d23063f16e61369316b5d`
- `src/scap_ng_tools/converter/direct04.py` — 14153 bytes — `e78735dbe508de2f20f41686816647fe0bf56ee39a5a541d251e37fb0943c9a2`
- `tests/test_converter_provenance.py` — 4233 bytes — `b1bd32a3b9766d2ca975ced0cb7a477ec821c94c21521ea2941ee4a6d918fca7`
- `scripts/build_issue28_conversion_ledger.py` — 5295 bytes — `03d2d4adf51c5084a726ecb7d041c06580ebb8d12a64e03a4e08a2cb3e3bf118`
- `scripts/build_issue28_feature_matrix.py` — 6922 bytes — `93d77ef769810c67a5bc668ef40d8d2893b55ed3af8fac1a6a8aa6a5ee66767a`
- `tests/test_issue28_manual_recovery.py` — 3205 bytes — `9b9805a1f185ca074f919a32c0c3479b1dc1e0ca7be33b1a7e02de2d9883b759`
- `docs/evidence/issue28/OVAL-FEATURE-COVERAGE.json` — 72896 bytes — `dd09e90f16566c7ee05e81a367aa3578524dafd7f4471489cd10356289b9169a`
- `docs/evidence/issue28/OVAL-FEATURE-COVERAGE.md` — 8445 bytes — `5166f127cca087690b6ea4b6d6d7f764ebe0cc78813aa3a247f6dbb30e686641`

## Preserved pipeline source copies

The small source-only pipeline subset is copied under `nov5-full65-pipeline/`; each file is listed in the JSON manifest. Generated outputs and receipts remain excluded.

## Excluded from Git commit

- **issue28 source ZIP copies**: `/home/u1239716047117002/Documents/scap-ng-vscode/.external/scap-ng-tools/.worktrees/issue28-variable-recovery/.issue28-sources` — source archives and bulk input data; retained in VM only; 65 ZIPs not committed.
- **issue28 analysis reports**: `/home/u1239716047117002/Documents/scap-ng-vscode/.external/scap-ng-tools/.worktrees/issue28-variable-recovery/.issue28-analysis` — large generated audit artifacts; retained in VM only; root and file hashes recorded below.
- **full65 pipeline scripts and receipts**: `/home/u1239716047117002/Documents/scap-ng-vscode/.external/full65-current/pipeline-issue27-20261105` — VM-local orchestration implementation; separate recovery work required; retained in VM only; root and file hashes recorded below.
- **full65 Stage A generated output**: `/home/u1239716047117002/Documents/scap-ng-vscode/.external/full65-current/automated-subset-7354a24cdbfe18321153ccaef5d772801a10cd71-20261105` — large generated corpus; retained in VM only; root and file hashes recorded below.
- **full65 Stage A repeat output**: `/home/u1239716047117002/Documents/scap-ng-vscode/.external/full65-current/automated-subset-repeat-7354a24cdbfe18321153ccaef5d772801a10cd71-20261105` — large generated corpus; retained in VM only; root and file hashes recorded below.
- **full65 Stage B source-preserving DRAFT**: `/home/u1239716047117002/Documents/scap-ng-vscode/.external/full65-current/draft-source-preserving-7354a24cdbfe18321153ccaef5d772801a10cd71-20261105` — 27,799-file generated DRAFT corpus; retained in VM only; root and file hashes recorded below.
- **Issue #26 receipts**: `/home/u1239716047117002/Documents/scap-ng-vscode/.external/issue26-receipts-20261105` — historical evidence bundle; not copied to PR; retained in VM only; root hash recorded below.

## Exact artifact roots

| Artifact | Files | Bytes | Tree SHA-256 |
|---|---:|---:|---|
| `issue28_sources` | 65 | 8613828 | `cb1c33b28db2895ceac104195f88e15218ee2be076e85288b6adc600801a98d9` |
| `issue28_analysis` | 5 | 45695731 | `4020345373609ff0fcfbcc40091a49b068cb1e79f89d1b6949cd53ccd13114e7` |
| `full65_pipeline` | 25 | 6128251 | `bb9749558ae7138d59d96ae999c4e18bfe7b20c881d408f874f7c3ee033a4be7` |
| `stage_a` | 18585 | 174041998 | `95804fed7f49a7dab5c2db0d21bead1e8dfb15dd0547c97369901ea17e924d25` |
| `stage_a_repeat` | 18581 | 168367230 | `4001c9dd1fccd28b1aa21cd126c9c81cc10ffada0cdcc369f93b6095f7168e11` |
| `stage_b` | 27803 | 325857200 | `70fc35825a2967bb7fa9d2c0fb4623b899028b938a9a3a5a75492a4a93380293` |
| `issue26_receipts` | 8945 | 66940967 | `702758ee0882b2402366cd4d8b2320226a16de569310c87d918784bf3e116ffa` |

The JSON manifest contains individual hashes for the 65 source ZIPs and the smaller Issue-28 analysis/pipeline trees. No source ZIP, generated corpus, credential, or private research file is committed.
