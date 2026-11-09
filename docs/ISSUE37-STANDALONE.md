# Standalone OVAL Variables through the production converter

Functional follow-up to [the separate toolchain/validation PR #38](https://github.com/vanderpol/scap-ng-tools/pull/38). No engine replacement or second installed converter. `scapng-convert-v04 --oval-definition ...` delegates to `convert_oval_definition` in the same facade and reuses its final API, semantic and JSON/YAML publication validation. `oval_variables.py` only indexes original XML and constrains the source lane; it has no evaluator or independent CLI.

| Pinned agnostic file | Definition suffix | Original Tests | Variables retained |
| --- | ---: | ---: | ---: |
| oval-def_constant_variable.xml | 92 | 2 | 2 |
| oval-def_variable_component.xml | 118 | 2 | 4 |
| ind-def_variable_test.xml | 538 | 4 | 2 |
| oval_check_enumeration_variable_values.xml | 170 | 10 | 2 |
| Total | 4 Definitions | **18** | 10 |

Source: `OVAL-Community/SCAP-Self-Assertion@e3538595c5083b9c34d937a81d319234df9bbfaa`, under `SCAP_1.4/OVAL_Test_Content/agnostic/`. These contain all 17 RI inventory candidates and the additional alias/regex sibling needed to preserve its complete Definition. Existing regex comparison syntax is retained; no regex/function execution is introduced.

## Source fidelity

- Whole original criterion trees, including negation, use the production visitor. Definition metadata/class/version, both original constant Tests and all Variable declarations remain; no Test projection is presented as a complete Definition.
- The standalone opt-in retains original-ID-based native identities and named Variable references. Identical constants keep independent identities; one-value aliases are not folded into literals. Existing STIG conversion defaults and all reviewed native/trace/coverage goldens remain unchanged.
- Source commit/path/SHA-256, original Definition/Test/Object/State/Variable identities, node hashes, dependency edges and native identity bindings are external provenance. If the input belongs to a Git checkout, original commit/path bytes must match. Otherwise the declared revision is labeled unverified; actual bytes remain SHA-pinned.
- Native `Test.variable` replaces source Object indirection without a fabricated Object. State identity predicates are conservatively rejected when not representable; they are never silently dropped. RHS `value@var_ref` remains a separate dependency with its own `value_match`.
- Only integer/string constants and same-datatype aliases are admitted. Observed/State or alias datatype conversion, external Variables, Object components and functions are explicit holds. Source cycles, wrong-kind/dangling references, duplicate identities and wrong hashes fail closed.

`source-trace.json` carries those mappings plus actual converter commit/source fingerprint, dirty-source flag, schema commit/digest and validation status. `conversion-scope.json` remains `CONVERTED_UNVERIFIED`, with no independent source/scanner proof. Raw XML and frozen schema bytes are unchanged; commit/path matching is not publisher/signature authentication.

The source adapter is not a new function interpreter. It does not resolve values for compliance, fabricate collected Items, apply clock/default-host data, or compute expected outcomes. Missing/error/empty populations, foreach, function contracts, datatype holds and virtual Item materialization decisions remain unchanged.

## Reproduction and qualification

Use the exact command in [README](../README.md), varying the file, original SHA-256 and Definition ID as recorded in `tests/test_oval_variables.py`. Never supply expected results to the converter or RI.

```sh
SCAP_NG_SCHEMA_ROOT=/path/to/pinned-flat-schema \
SCAP_NG_OVAL_TEST_CONTENT=/path/to/pinned-SCAP-Self-Assertion \
PYTHONPATH=src python -m unittest discover -s tests -p test_oval_variables.py -v
```

The full flat-schema CI lane also supplies the four signed NIWC fixtures and official OVAL XSD checkout. It tests actual JSON/YAML written by the sole production CLI, independent original-source identity/alias joins, final malformed-output rejection, casts/functions/cycles/identity negatives and original STIG golden preservation. Runtime/helper provenance explicitly records the new opt-in visitor adaptation while retaining prior hashes.

RI handoff is a separate execution step. The existing approved Go evaluator does not yet accept Variable declarations/Test.variable or complete multi-Test Evaluate AND Assessments. Preserve actual unsupported diagnostics and report zero computed Variable Tests until that shared-runtime increment is approved; schema success is not execution proof. Scalar constants then same-datatype aliases are the recommended first RI increment, with the virtual-population and broader status/function holds preserved.
