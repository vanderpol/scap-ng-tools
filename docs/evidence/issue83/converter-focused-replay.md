# Focused current-converter replay

This receipt exercises the production converter against cached positive source
witnesses. It is not an expected-outcome or RI runtime-equivalence claim.
The qualification runner now verifies the exact flat 0.4.1 schema family before
starting any converter subprocess; a legacy/parallel schema directory is
rejected rather than being recorded as the requested pin.

Pins:

- Tools converter commit: `aba2b0b5e8e247b26332969a6be1d3bf4814eb53`
- Canonical SCAP-NG commit: `5ee55288b369da26f308f40813e545b78dff2753`
- Flat schema family SHA-256: `88fc59791f9cb5055d2a8dc27bb458bcf6699b5820061ce68af1a355bd33a84f`
- Self-Assertion source: `e3538595c5083b9c34d937a81d319234df9bbfaa`
- Witness receipt SHA-256: `d4741fdae77705015bdbe060f5be8b35ea88cc01b7cf0062660fd7ddec32018e`

## Results

- `agnostic/oval-def_criteria.xml`: 2/2 converted (`tst:123`, `tst:966`)
  - Receipt: `/tmp/tools-issue83-current-conversion-criteria3-1795106996/receipt.json`
  - SHA-256: `933114a088fb38a5674c7f84bd1a2310364735a171e1d53ffa8e4d6ecaaf15c4`
- `agnostic/oval_existence_enumeration.xml`: 12/12 converted
  - Receipt: `/tmp/tools-issue83-current-conversion-existence2-1795106996/receipt.json`
  - SHA-256: `90ceca81f5e4f521c810e0de1e1bb1688e99e1c8babbe66291be251262c714c0`

All output retains source Test IDs/hashes, witness hashes, source traces and
conversion-scope hashes. Runtime evaluation and independent OVAL equivalence
remain unproved.
