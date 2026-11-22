# Candidate 0.4.1 contract: OVAL external-variable restrictions

**Status: proposal only.** This document does not change the canonical schema, converter, RI, or semantic pack. It is the review artifact requested before any canonical amendment. The candidate names are intentionally isolated under `candidate_native_shape`; they must not be emitted by the production converter until the canonical owner accepts the contract.

## Exact review pins and source evidence

| Artifact | Pin / digest |
|---|---|
| OVAL source schema | `OVAL-Community/OVAL@2f140ee5c5dd1ed9606fcd5afc301f6baeb48706` (5.12.3) |
| OVAL source XSD | `oval-schemas/oval-definitions-schema.xsd`, `external_variable`/`PossibleValueType`/`PossibleRestrictionType`/`RestrictionType` |
| Self-Assertion source | `OVAL-Community/SCAP-Self-Assertion@d91e6ba33841e3202dc27d3e0d469a7abd939b16` |
| Source member | `SCAP_1.4/OVAL_Test_Content/agnostic/oval-def-ext.zip!oval-def-ext.xml` |
| Source ZIP SHA-256 | `6ff45b5a85b77eadce11397d30adbdd011eb1d32fa3566d23b60322597ac5bdf` |
| Source XML member SHA-256 | `df3a7bfbcf54b48652ed5c5ece93131c4c82ac2f07ff4056f5ed4668160dc8c1` |
| Qualification fixture member | `oval-def-ext_external-variables.xml`, SHA-256 `dc534d77edf48eb813ab0840689e0700a96f98322a1bc0d0164b1734c43b85d1` |
| Active canonical schema | `vanderpol/scap-ng@f51ab2c5bd82c94a9c292a7abb2ef1a7edc91ca2` |
| Canonical flat schema family | SHA-256 `11b5ae735dd0a7a1db496b421e0d12f757c027f734da688c2b1d96940f4c47dc` |
| Assessment execution closure | SHA-256 `9873247ae54f5d9b7ba77f487f8e33f96b791f30c181c8e15f3931a2afcfdf4b` |
| Current Tools baseline | `vanderpol/scap-ng-tools@07f32481c34e1b1e8acfdd4d580e8980245d7527` |

The source XML is XSD/Schematron-valid at the cited corrected source pin. The source correction in that pin concerns Solaris `package511` Variables; it does not alter `def:562`.

## What OVAL requires

The pinned XSD says that an `external_variable` receives its actual value(s) from outside the OVAL document. Its `possible_value` and `possible_restriction` children together form an **OR** list of permitted alternatives. A `possible_value` is one typed value. A `possible_restriction` is a branch containing one or more typed `restriction` predicates; predicates within that branch are combined by its `operator`, whose default is `AND`. `hint` is explanatory metadata and is not a value or executable predicate.

The external source remains responsible for supplying the value. A companion `oval-def-ext_external-variables.xml` is a qualification fixture, not an OVAL authoring default and not a converter input binding.

## Candidate native representation (not yet canonical)

Retain the existing Input contract and add a typed restriction collection alongside `constraints.allowed`; do not overload `allowed` with regexes or relation objects:

```yaml
inputs:
  source-external-variable-input:
    datatype: string                 # inferred native type, source datatype retained in provenance
    cardinality: one_or_more         # independent of restrictions and requiredness
    required: true
    constraints:
      allowed: ["fixed-value"]      # possible_value branches, each exact typed equality
      predicate:                       # generic value predicate expression
        or:                             # alternatives are explicitly ORed
          - matches_regex: "^[0-9]{3}-[0-9]{3}-[0-9]{4}$"
```

The candidate semantics are:

1. Each `allowed` member is one `possible_value` branch and is compared as an exact value in the declared datatype. It is not a default.
2. Each `predicate` expression branch is one `possible_restriction` branch. Each comparison leaf is typed in the declared datatype and retains the source operation and lexical value in provenance. The group operator is `and`, `or`, `one`, or `xor`, matching the pinned OVAL operator vocabulary; omitted source operator means `and`.
3. The complete constraint is the OR of every `allowed` branch and every restriction-group result. A declaration with no branches accepts values only after datatype validation, as OVAL specifies.
4. The representation is generic and applies to all supported OVAL datatypes and operation combinations admitted by the source schema. The four Boolean nodes are the existing generic `and`, `or`, `one`, and `xor` expression forms; there is no OVAL-specific restriction-group runtime type. It must not special-case telephone-number regexes or `def:562`.
5. No regex engine or comparison operation is implicitly enabled by a source `hint`; the operation is required and the canonical evaluator owns its typed semantics and limits.
6. Source operations that the canonical language does not admit remain an explicit conversion hold. The converter must never emit an unconstrained Input after dropping a restriction.

`source_operation` is provenance in this sketch, not a second evaluator operation. The final canonical name/enum must be chosen from the existing 0.4.1 comparison vocabulary or an owner-approved amendment; no converter-only alias is proposed.

## Binding, cardinality, and status contract

| Situation | Required behavior in this proposal |
|---|---|
| Invocation supplies a value | Bind it explicitly to the declared Input and record binding source/provenance. Validate datatype, cardinality, then all branches. |
| Invocation omits a required Input | Do not use a source fixture, XCCDF default, or empty list. Produce `not_evaluated` with a stable missing-required-input reason; no collection or compliance verdict is produced. |
| Invocation omits an optional Input | Omission is distinct from an explicitly supplied empty value. It is allowed only on a path dominated by the existing `input_provided` guard; an unguarded consumer is an authoring error, never defaulted. |
| Supplied value has the wrong datatype or invalid lexical form | Reject the binding without coercion; produce `error` with a typed-input diagnostic. |
| Supplied value violates all allowed/restriction branches | Reject the binding with `error` and an input-constraint-violation reason. Do not turn a bad policy input into a host FAIL or PASS. |
| Supplied value count violates `cardinality` | Reject the binding with `error`; cardinality validation is independent of branch validity. |
| `zero_or_more`/`one_or_more` empty population | Preserve explicit empty as a supplied population. It is not omission; validity is determined by cardinality and consumer semantics. |
| Restriction malformed or unsupported | Reject conversion/schema admission or the binding explicitly. Never silently remove the restriction. |

`cardinality` belongs to the Input contract; `required` answers whether a binding must be present. Neither field is inferred from the number of values in the Self-Assertion fixture. The converter must inspect the source consumer graph and fail closed when no sound cardinality mapping exists. For `def:562`, the source variable object/test closure requires at least one value for the `at_least_one_exists` checks, but that is a source-consumer fact, not evidence that the companion fixture should become a default.

The status choices above align with current 0.4.1 language documentation: missing required input is `not_evaluated`; invalid supplied content is an `error`; optional omission requires an explicit `input_provided` guard. The canonical owner should confirm that status/reason codes and the exact binding-time boundary are the accepted wire contract before schema work begins.

## `def:562` acceptance mapping

The blocked Definition is titled “Evaluate to true if the oval-def:external_variable construct is properly supported.” Its relevant closure is:

| Source ID | Source use | Expected branch contract |
|---|---|---|
| `oval:org.mitre.oval.test:var:629` | `tst:509`, one `possible_restriction` | string, one AND group, `pattern match` `^[0-9]{3}-[0-9]{3}-[0-9]{4}$` |
| `oval:org.mitre.oval.test:var:327` | `tst:439`, two `possible_restriction` branches | string, OR between the two one-predicate groups; accepts `123-456-7890` or `1-123-456-7890` |
| `oval:org.mitre.oval.test:var:642` | `tst:132`, one `possible_value` | int, exact allowed value `0` |
| `oval:org.mitre.oval.test:var:863` | `tst:275`, two `possible_value` branches | int, exact allowed values `0` or `1` |

The source tests use `check_existence="at_least_one_exists"` and `check="all"`. The candidate must preserve those Test semantics separately from Input validation. A successful conversion still requires RI execution with explicitly supplied bindings; source expected TRUE must not be fed into the evaluator.

## Required conformance vectors before implementation

The machine-readable companion `external-variable-restriction-proposal.json` contains 24 vectors for:

- allowed-only positive `0`/`1` and negative `2`;
- one string regex group positive and negative;
- two restriction groups, proving both OR branches and a nonmatching value;
- typed numeric restriction positive and negative;
- wrong datatype/lexical value;
- missing required binding;
- optional unbound with and without an `input_provided` guard;
- empty and multivalue cardinality cases;
- all four Boolean operators (`and`, `or`, `one`, `xor`);
- optional guarded and unguarded Input use;
- malformed expressions and bounded branch/pattern resource limits;
- source fixture values marked non-authoritative.

The vectors are contract-review material, not production evaluator tests. Once the owner accepts the contract, the same vectors should be implemented in canonical schema tests, Tools conversion tests, RI binding/evaluator tests, and editor validation tests. Each implementation must add malformed/unsupported-operation negatives and bounded regex/resource tests.

## Decision requested

Approve or amend the candidate restriction-group shape, operation vocabulary, cardinality derivation rule, and the `not_evaluated` versus `error` binding outcomes. Until that decision, keeping `def:562` as `canonical_input_constraint_hold` is correct and the converter must remain fail-closed.

## Direct schema pointers

The source evidence is not inferred from the benchmark diagnostic. The relevant pinned-XSD declarations are:

- `oval-definitions-schema.xsd#/xs:schema/xs:element[@name="external_variable"]` — unbounded choice of `possible_value` and `possible_restriction`, and the source statement that branches are ORed;
- `oval-definitions-schema.xsd#/xs:schema/xs:complexType[@name="PossibleValueType"]` — one `anySimpleType` value plus required `hint`;
- `oval-definitions-schema.xsd#/xs:schema/xs:complexType[@name="PossibleRestrictionType"]` — one or more `restriction` children, `operator` default `AND`, required `hint`;
- `oval-definitions-schema.xsd#/xs:schema/xs:complexType[@name="RestrictionType"]` — `anySimpleType` value plus required source `operation`;
- `oval-common-schema.xsd#/xs:schema/xs:simpleType[@name="OperatorEnumeration"]` and `OperationEnumeration` — authoritative operator/operation vocabularies.

The current canonical Input pointers are `/properties/assessment/properties/inputs/additionalProperties/properties/{datatype,cardinality,required,constraints}` and `/properties/.../constraints/properties/allowed`. The last pointer is the exact present gap: it has no typed restriction-group member. No pointer under the candidate proposal is active canonical schema.
