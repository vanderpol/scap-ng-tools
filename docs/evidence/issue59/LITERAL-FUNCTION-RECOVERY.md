# Literal-only `escape_regex` and `glob_to_regex` recovery

This cycle adds a source-proven adapter for two OVAL 5.12.3 functions that
have no active SCAP-NG 0.4.1 function node. It lowers only finite literal or
constant-string inputs to typed native string literals. Dynamic operands remain
blocked; no function grammar or schema was added.

## Pinned source evidence

- OVAL Community 5.12.3: `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`.
- Canonical schema: `aece827964c785be77b088c3c61255a2d07fd9a9`, aggregate
  `578315d1e00bd39449ed597ed3d39555384276bd36198a54ca0b1e3c17e72829`.
- `escape_regex` witness: `oval-def_escape_regex_function.xml`, SHA-256
  `4e561d9ca7db1cfe33035e78d906b3860ce555a86f459c1e5132c6ba354b6433`.
  Its two local Variables have literal/constant-string operands; each value
  is escaped independently and collection order is retained.
- `glob_to_regex` witness: `oval-def_globtoregex_test.xml`, SHA-256
  `fb061d16c22c204d5ea9e7cbdb6a9bfff530136f9af340dd5cd9870ebde3d587`.
  All 20 operands are string literals. The adapter preserves the pinned
  anchored regex vectors, slash boundaries, hidden-name guards, bracket
  classes, and `glob_noescape` behavior.

The conversion is a compile-time transformation of closed source values, not
an implicit cast or runtime evaluation. Invalid glob classes and non-string or
dynamic operands fail closed.

## Measured result

The standalone rebuild improved from **100/168 Definitions and 532/803 Tests**
to **102/168 Definitions and 554/803 Tests**. Independent parity now reports
**zero converted-parity failures** and the same two source-invalid Variable
holds (`var:589` and `var:540`). The complete 65-benchmark source-ID rebuild
remains **6,489 converted / 98 blocked / 1,403 manual-only**, with zero
converted-to-blocked regressions.

Receipt: [`literal-function-cycle.json`](literal-function-cycle.json).
No RI execution, SCC proof, or scanner equivalence is claimed.
