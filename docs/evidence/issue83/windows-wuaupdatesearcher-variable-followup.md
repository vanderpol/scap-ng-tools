# Windows Windows-Update Variable datatype follow-up

- Source correction: [Self-Assertion PR #13](https://github.com/OVAL-Community/SCAP-Self-Assertion/pull/13)
- Converter context: [Tools PR #84](https://github.com/vanderpol/scap-ng-tools/pull/84)
- Machine receipt: `windows-wuaupdatesearcher-variable-followup.json`

The baseline/candidate SHA-256 values were independently recomputed from exact Git blobs. The source referenced `var:4` from a boolean State entity while declaring that constant Variable as string. PR #13 changes the Variable declaration to boolean, preserves OVAL boolean values `0`/`1` and `var_check="at least one"`, and increments the Definition/Variable versions. The baseline was blocked; the candidate converts schema-valid. Runtime and independent equivalence remain unproved.
