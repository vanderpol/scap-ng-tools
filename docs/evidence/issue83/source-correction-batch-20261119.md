# Focused source-correction replay — 2026-11-19

This receipt replays existing proposed Self-Assertion source corrections through the production Tools converter. It does not replace the pinned baseline or claim source/runtime equivalence.

Pins:

- Baseline source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`
- Converter: Tools `c6132809220f4214ba5b4842797a2b7fd0125df8`
- Canonical schema: `vanderpol/scap-ng@5ee55288b369da26f308f40813e545b78dff2753`

## Transitions

| Transition | Cases |
|---|---:|
| blocked → `CONVERTED_UNVERIFIED` | 6 |
| blocked → removed by source correction | 2 |
| blocked → blocked | 1 |
| already converted → unchanged | 4 |

Recovered cases include agnostic merge datatypes, macOS environment/NVRAM, Windows audit/update witnesses, UNIX password/SSHD/text recursion, and the macOS keychain witness. Solaris deprecated package witnesses are removed by PR #15. Windows registry effective-rights remains blocked after PR #11 because the remaining failure is a canonical/schema representation hold, not the removed deprecated group behavior.

Every case retains exact source branch commit, source XML SHA-256, Definition/Test IDs, status and corrected artifact hashes in the JSON receipt. Native conversion is authoring/schema validation only; no runtime execution or independent OVAL equivalence is claimed.
