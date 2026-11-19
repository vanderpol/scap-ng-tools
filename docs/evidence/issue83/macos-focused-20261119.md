# macOS Self-Assertion focused replay — 2026-11-19

This receipt reruns the 20 pinned macOS/UNIX-on-macOS Definition files through the current production Tools adapter, rather than relying on the stale full-corpus ledger.

- Source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`
- Converter implementation: `17e9d07944acb58f7ecb146471a301514df8fc97`
- Canonical schema: `vanderpol/scap-ng@5ee55288b369da26f308f40813e545b78dff2753`
- Schema family SHA-256: `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`
- Result: **17 converted, 3 blocked**

Remaining source-linked blockers:

1. `macos/ind-def_environmentvariable58_test_mac.xml`, `def:1`: source Variable cast outside the bounded proof; corrected source candidate is tracked in Self-Assertion PR #6.
2. `macos/macos-def_keychain_test.xml`, `def:20002`: deprecated `environmentvariable_object`; corrected source candidate is PR #12 and independently qualified in its companion receipt.
3. `macos/macos-def_nvram512_test.xml`, `def:448`: source generator metadata declares OVAL 5.10.1 while the content uses 5.12.3 constructs; corrected source candidate is PR #8.

All 17 converted rows remain `CONVERTED_UNVERIFIED`; no runtime or independent OVAL equivalence is claimed. See the JSON receipt for exact source hashes, IDs, diagnostics, timings, and output hashes.
