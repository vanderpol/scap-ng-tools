# Issue #28 exhaustive OVAL Variable datatype inference audit

This is a read-only audit of all 65 pinned source archives. It does not alter a source `datatype`, add an implicit cast, or promote a Rule. The complete machine-readable inventory (all 2,385 Variables, all 8,892 Rules, source hashes, declarations, expression trees, check-selection provenance, and per-benchmark summaries) is [`OVAL-VARIABLE-DATATYPE-INVENTORY.json.gz`](OVAL-VARIABLE-DATATYPE-INVENTORY.json.gz).

## Scope and receipt

| Item | Result |
| --- | --- |
| Pinned benchmarks | 65 |
| Source Rules | 8,892 (owner baseline 8,892) |
| Variables | 2,385 (1,397 local, 552 constant, 436 external) |
| Variable-component dependency edges | 1,356; unresolved 0; cycles 0 |
| OVAL schema | 5.12.3, SHA-256 `06b79e8683d6b9dcaad3ab074a456588ed82c4edd2e8fff209def10aa0a366cc` |
| Source revision | `niwc-atlantic/scap-content-library@8c8e5dff860af6b1290ee9273a282db24278f8d5` |

The source XCCDF selection inventory is also retained: **7,239 Rules have OVAL**, **7,239 have OCIL**, **7,239 have both**, and **1,653 are OCIL-only**. This audit does not change the owner decision that OVAL is preferred when both exist and OCIL-only Rules remain manual.

## Contract audited

The pinned XSD states that a Variable’s returned values must comply with its required `datatype`; otherwise evaluation reports an error, and `record` is prohibited on Variables. The FunctionGroup documentation permits an attempted cast when a *component* is supplied to a function with the wrong type. That component boundary is not a general cast of a completed function result into its enclosing `local_variable/@datatype`. The audit therefore records both the declared type and the function-result type; it never treats schema acceptance as proof.

| OVAL function | Result value datatype | Cardinality behavior | Corpus occurrences |
| --- | --- | --- | ---: |
| `arithmetic` | integer, float | single unless an operand is a collection; Cartesian product then collection | 9 |
| `begin` | string | single or collection of strings | 0 |
| `concat` | string | single or collection over component combinations | 750 |
| `count` | integer | one integer; flatten/count all represented values | 47 |
| `end` | string | single or collection of strings | 3 |
| `escape_regex` | string | single or collection of strings | 0 |
| `glob_to_regex` | string | single string | 0 |
| `merge` | string | one string | 106 |
| `regex_capture` | string | single or collection, one per input | 320 |
| `split` | string | collection; preserves order and empty tokens | 29 |
| `substring` | string | single or collection, one per input | 21 |
| `time_difference` | integer | single or collection of integers | 0 |
| `unique` | string | single or collection of strings | 63 |

Counts are occurrences in Variable expressions, including nested functions. `arithmetic` remains a domain of integer/float until operands are independently known; object fields and external values are runtime-dependent.

## Inference inventory

| Classification | Variables | Meaning |
| --- | ---: | --- |
| `component_result_source_dependent` | 212 | A local component result depends on collected object values; declaration is preserved and no inferred value type is asserted. |
| `constant_declared_datatype` | 552 | Constant values retain their explicit declaration; lexical validity is recorded separately. |
| `explicit_result_datatype_mismatch` | 31 | Known function result domain excludes the declared Variable type; conversion requires source-result casting or source repair and is not silently recovered. |
| `external_declared_datatype` | 152 | No possible-value/restriction children; only the declared external type constrains runtime input. |
| `external_declared_datatype_with_constraints` | 284 | External type plus source possible-value/restriction metadata; no value inference is invented. |
| `function_result_compatible` | 1,154 | Function result domain includes the declared Variable type under the OVAL function contract. |

## Result mismatches

The exhaustive pass finds **31 Variable declarations across 13 source Rules** whose known function result domain excludes the enclosing declaration. This is a broader source audit than the **eight active function-recovery Rules** currently remaining in the converter ledger. The eight are the three arithmetic Rules (string declaration), four Cisco split Rules (integer declaration), and one IIS count Rule (string declaration). The other five source Rules contain additional function-result mismatches but are already governed by other blockers or are not the primary remaining function-recovery candidates; they must not be represented as independently proved.

| Function | Mismatching Variable records | Unique Rules | Active recovery Rules |
| --- | ---: | ---: | ---: |
| `arithmetic` | 3 | 3 | 3 |
| `concat` | 4 | 4 | 0 |
| `count` | 2 | 1 | 1 |
| `merge` | 4 | 4 | 0 |
| `regex_capture` | 8 | 4 | 0 |
| `split` | 4 | 4 | 4 |
| `substring` | 6 | 1 | 0 |

### Every mismatching source Variable

| Benchmark | Source Rule(s) | Variable IDs | Declared | Function result |
| --- | --- | --- | --- | --- |
| `U_Amazon_Linux_2023_V1R2_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip` | 274067 | `25815500` | string | `arithmetic` → float/integer |
| `U_Cisco_IOS-XE_Router_NDM_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` | 215833 | `21583304`, `21583305`, `21583307`, `21583310` | integer | `merge, regex_capture, split` → string |
| `U_Cisco_IOS-XE_Switch_NDM_V3R5_STIG_SCAP_1-4_Benchmark-enhancedV6-signed.zip` | 220544 | `22054404`, `22054405`, `22054407`, `22054410` | integer | `merge, regex_capture, split` → string |
| `U_Cisco_IOS_Router_NDM_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV6-signed.zip` | 215688 | `21568804`, `21568805`, `21568807`, `21568810` | integer | `merge, regex_capture, split` → string |
| `U_Cisco_IOS_Switch_NDM_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV6-signed.zip` | 220596 | `22059604`, `22059605`, `22059607`, `22059610` | integer | `merge, regex_capture, split` → string |
| `U_MS_IIS_10-0_Server_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip` | 218814 | `21881401` | integer | `concat` → string |
| `U_MS_IIS_10-0_Site_V2R14_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 218762 | `21876201` | integer | `concat` → string |
| `U_MS_IIS_10-0_Site_V2R14_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 218771 | `21877101`, `21877102` | string | `count` → integer |
| `U_MS_IIS_10-0_Site_V2R14_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip` | 218778 | `21877801` | integer | `concat` → string |
| `U_MS_IIS_8-5_Site_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` | 214492 | `440` | integer | `concat` → string |
| `U_Oracle_Linux_7_V3R3_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip` | 221718 | `4189`, `4190`, `4191`, `4212`, `4213`, `4214` | integer | `substring` → string |
| `U_Oracle_Linux_9_V1R4_STIG_SCAP_1-4_Benchmark-enhancedV5-signed.zip` | 271596 | `25815500` | string | `arithmetic` → float/integer |
| `U_RHEL_9_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip` | 258155 | `25815500` | string | `arithmetic` → float/integer |

The JSON contains the original XML declaration for every function-bearing or mismatching Variable. Source SHA-256, component IDs, nested function list, cardinality, and all associated Rule IDs are retained for review.

## Semantic cases and evaluator evidence

- **Positive numeric:** arithmetic with integer operands produces an integer; with a float operand it produces a float. A string-declared enclosing Variable is not made equivalent merely because an evaluator may serialize the result as lexical text.
- **Positive count:** count over two singleton components returns one integer; count over collections counts all represented values, including nested `unique` output.
- **Split boundaries:** `"-a-a-"` with `"-"` yields `"", "a", "a", ""`; `"---"` yields four empty strings. Empty tokens are values, not missing defaults.
- **Conversion errors:** integer conversion of `"1,x"` fails on `x`; an empty string cannot be cast to integer. Missing object items and failed function inputs remain OVAL error/unknown conditions, not zero or empty defaults.
- **Cartesian evaluation:** arithmetic and other multi-input functions preserve collection expansion, ordering, and duplicates according to the pinned FunctionGroup contract.

The existing OpenSCAP 1.3.9 receipt in [`OVAL-FUNCTION-DATATYPE-EVALUATOR.txt`](OVAL-FUNCTION-DATATYPE-EVALUATOR.txt) observes numeric-to-string and per-value split-to-int behavior with `--skip-validation`. OpenSCAP advertises OVAL 5.11.1, so this is evaluator behavior evidence only—not independent OVAL 5.12.3 equivalence proof. No SCAP-NG compiler/runtime executable is present in the checked-out schema/tools repositories.

## Design decision recommendation

**0.4.0: do not make a breaking grammar or schema change.** Keep `datatype` explicit and required, retain the current static compatibility check, and publish diagnostics/evidence. Do not omit declarations, override source declarations, or add a generic hidden cast. This is the only safe behavior for object-collected fields, external/organizational inputs, empty populations, conversion errors, unknown/not-collected statuses, and nested Variables.

**0.5.0: consider an owner-approved explicit cast contract only as a separate language decision.** A candidate representation is an explicit typed wrapper around an expression (for example `function: {name: cast, arguments: [...], options: {datatype: string}}`), but it is not in the canonical 0.4 grammar and is not implemented here. Its contract would need to define lexical conversion, per-value collection behavior, order/duplicates, empty and error propagation, numeric widening, and proof vectors. A declaration-inference mode is a weaker alternative because it cannot soundly infer dynamic object/external values and would create migration ambiguity.

## Qualification status

- 65/65 benchmarks and 8,892/8,892 source Rules are inventoried.
- 2,385/2,385 Variables are inventoried; 31 known result/declaration mismatches remain explicitly recorded.
- No source declaration, historical golden, manual alternative, schema grammar, or VS Code editor was modified.
- No mismatch is claimed recovered or independently proved. The eight active candidates remain owner-decision dependent; the 23 additional mismatch records remain source-audit findings and are not silently reclassified.
- Tests assert the pinned counts, function domains, mismatch grouping, provenance, cardinality invariants, lexical boundary cases, and no implicit-cast conclusion.

## Per-benchmark accounting

The `benchmarks` array in the machine-readable inventory is the complete 65-row ledger. It retains each source filename/hash, Rule count, check selection counts, Variable counts, function occurrence counts, mismatch records, and all Rule/Variable provenance. This avoids duplicating a large generated table in prose while keeping the artifact deterministic and reviewable.
