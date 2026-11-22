# `def:562` external Variable conversion — 2026-11-21

OpenSCAP 1.3.9 source validation (`oscap oval validate`) passed for the exact corrected Self-Assertion XML. This is source validation only, not runtime equivalence.

The exact corrected Self-Assertion source at `OVAL-Community/SCAP-Self-Assertion@d91e6ba33841e3202dc27d3e0d469a7abd939b16` now converts through the production Tools path.

- Source archive: `6ff45b5a85b77eadce11397d30adbdd011eb1d32fa3566d23b60322597ac5bdf`
- XML member: `df3a7bfbcf54b48652ed5c5ece93131c4c82ac2f07ff4056f5ed4668160dc8c1`
- Definition: `oval:org.mitre.oval.test:def:562`
- Canonical: `c428fd0708da0cdd574dc9e499db714a1068bd75`, flat schema `1755c893712ef30334dc7ecadc88e5abf387c2d60a75211bc2445b7cefa2e7d4`
- Result: **18/18 Tests converted, schema/semantic validated; runtime and independent equivalence not run**.

The Definition contains 18 reachable external Variables: 14 unrestricted Variables become required typed Inputs with **no constraints and no default**, while 4 restricted Variables preserve `possible_value` as `constraints.allowed` and `possible_restriction` as `constraints.predicate`. All 18 consumer-derived cardinalities are `one_or_more`; no sibling source declarations or fixture values are imported.

The exact production command and output hashes are in [`external-variable-def562-after-20261121.json`](external-variable-def562-after-20261121.json). Two clean runs were byte-identical.
