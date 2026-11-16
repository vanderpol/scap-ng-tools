# Issue #59 — closed enum Variable datatype recovery

This cycle removes the obsolete declaration-level `datatype` assumption from
the enum projection path. It derives a Variable's type from its native typed
literal, Variable-reference, and closed `unique` expression graph. Canonical
typed literal arrays are accepted; mixed or unresolved graphs remain blocked.
No implicit cast, source datatype guess, or schema change is introduced.

## Pins and evidence

- Canonical SCAP-NG schema: `aece827964c785be77b088c3c61255a2d07fd9a9`
  (flat-family SHA-256 `578315d1e00bd39449ed597ed3d39555384276bd36198a54ca0b1e3c17e72829`).
- OVAL Community 5.12.3: `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`.
- Standalone SCAP Self-Assertion: `e3538595c5083b9c34d937a81d319234df9bbfaa`.
- Converter worktree base: `fb5104b81b2def53151bad94db5218986227969f` (dirty during this cycle).

The source declaration remains in provenance. The native expression is the
only datatype authority under the active 0.4.1 contract. A declaration whose
source datatype conflicts with its closed expression is retained as a
source-invalid parity hold rather than coerced.

## Measured standalone gate

The rebuilt 145-document corpus contains 168 Definitions and 803 Tests. It
produces **104 converted Definitions / 62 blocked / 2 owner-excluded** and
**579 converted Tests / 222 blocked / 2 owner-excluded**. Independent parity
checks qualify 102 Definitions and 585 mapped Tests, with **zero converted
parity failures** and two explicit source-invalid holds (`var:589` and
`var:540`). The exact-head semantic pack was regenerated from OVAL Community 5.12.3 and the canonical schema; it contains 53 capabilities (including `unix.sshd`) and has SHA-256
`2903f815f04b0913b886a685f91a8d34f4125e117bc747dbf824ddd073a64629`. The refreshed pack manifest SHA-256 is
`4b3745fae6d0bfca0a3387056d825d5a41c7aa3c88e08e01058b7d6b225dcd6d`; the
Tests ledger SHA-256 is
`7cb6c2f53709131e79007c31761732dd57a6888e69da16c5786113ea360ebded`; the
parity receipt SHA-256 is `904ddf943f355fec916d95a836e4c9af33400ee6291b59bfd10f56703ed935cb`.

This is structural/source parity only: no scanner execution, RI equivalence,
or expected-outcome claim is made.

The full-65 rebuild receipt (`full65-enum-cycle.json`, SHA-256
`f5e2ed174cd7459570197659b8c5773fa6b0eb141189fbd50ccf3b17eedf4f40`)
contains **6,489 converted / 98 blocked / 1,403 manual-only**, recovering 10
blocked Rules and introducing zero converted-to-blocked regressions. Source ZIP hashes and the pinned source Git revision pass. The remaining 98
blocked Rules are 14 schema-semantic, 78 unsupported-capability, and 6
unsupported-construct cases; they are not reclassified as manual or converted.
