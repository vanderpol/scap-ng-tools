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
- `agnostic/oval-def_time_difference_function.xml`: **30/30 converted**
  - Receipt: `/tmp/tools-issue83-current-conversion-time-difference-1795107056/receipt.json`
  - SHA-256: `a872b08f2fa0a0418c33e2363b7fafb14b495eba477b0ceedd65ffe5979937a6`
- `agnostic/oval-def_regex_capture_function.xml`: **4/4 converted** (authoring
  conversion only; runtime regex qualification remains separate)
  - Receipt: `/tmp/tools-issue83-current-conversion-regex-1795107133/receipt.json`
  - SHA-256: `2691057366984314171722af808de7b233a8d46b68db26240b570a72dc6c3499`
- `agnostic/oval-def_split_function.xml`: **5/5 converted**
  - Receipt: `/tmp/tools-issue83-current-conversion-split-1795107159/receipt.json`
  - SHA-256: `b71794f6bddc6edfc36b55ec851c13769df254a305d2a3bf4eaa057c98ac8920`
- `agnostic/oval-def_globtoregex_test.xml`: **20/20 converted** (authoring
  conversion only; runtime regex qualification remains separate)
  - Receipt: `/tmp/tools-issue83-current-conversion-glob-1795107159/receipt.json`
  - SHA-256: `de85685066796f2d027722631f8a0998da01f9b0915f66705ccaf1e4b6389504`

- `agnostic/oval-def_variable_component.xml`: **2/2 converted**
  - SHA-256: `02608dc9dca2197eb02dcadbf2e428236e183427255152f401b1db9945695b38`
- `agnostic/oval-def_constant_variable.xml`: **2/2 converted**
  - SHA-256: `fec7fc532e6a93d2305ca1bfd78a08f57fa1e85ef74a0d49fdbc77899075ff00`
- `agnostic/oval-def_local_variable.xml`: **2/2 converted**
  - SHA-256: `b4c440ebeee249eadcbc42518654f2725c10324da754c2d79b778ccbe1201835`
- `agnostic/oval_check_enumeration_variable_values.xml`: **10/10 converted**
  - SHA-256: `980b586d5cebe8bc4d31e0c271e815a3bc620af5da194fd5a3bc59bdf39a4754`

All output retains source Test IDs/hashes, witness hashes, source traces and
conversion-scope hashes. Runtime evaluation and independent OVAL equivalence
remain unproved.
