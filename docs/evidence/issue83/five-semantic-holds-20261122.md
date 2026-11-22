# Five Self-Assertion semantic-hold reconciliation — 2026-11-22

This ledger reconciles the five historical parity holds against the current
production conversion and current local RI evidence. It does **not** change
converter behavior or promote runtime evidence to independent OVAL equivalence.

## Result

- Current pinned source `OVAL-Community/SCAP-Self-Assertion@d91e6ba`:
  **167/167 Definitions and 799/799 Tests converted and canonical-schema
  validated**.
- Current local 65-benchmark replay: **6,493 converted, 94 blocked, 1,403
  manual-only**, with **14 recovered**, **0 converted-to-blocked regressions**.
- `def:38` and `def:580`: native RI result **TRUE** in the bounded VM P0
  receipt; independent OVAL equivalence remains unproved.
- `def:562`: merged Tools conversion is complete and source-linked; its 18
  external bindings still require RI execution with explicitly supplied
  Inputs.
- macOS keychain and Solaris `package511`: no demonstrated converter datatype
  defect. Both remain runtime/equivalence holds because no qualified host
  execution was performed.

## Important corrections to the old ledger

- `def:562` is **not** a current converter blocker. PR #112 is merged; the
  native assessment contains all 18 Tests, four restricted Inputs, fourteen
  unrestricted Inputs, consumer-derived `one_or_more` cardinality, and no
  implicit fixture/default. Remaining work belongs to RI.
- macOS `keychain_object/filepath` is an OVAL `EntityObjectStringType` and is
  mapped to native `filepath` with datatype `string`. The old “datatype
  unresolved” parity message is not proof of a mismatch; it is an execution /
  equivalence-checker boundary.
- Solaris `package511` is not deprecated. The historical 15 Schematron reports
  were from the pre-`d91e6ba` source. PR #35 changed the two variable
  declarations from `string` to `version`, and the corrected source is recorded
  as 143/143 XSD-valid and Schematron-clean.

The machine-readable ledger contains exact source, native artifact, schema, RI,
and receipt hashes: `five-semantic-holds-20261122.json`.
