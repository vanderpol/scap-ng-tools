# XCCDF Value relational-constraint adapter

The pinned corpus contains five active Rules whose selected OVAL check exports an
XCCDF `Value` with a non-equality operator. These are converter gaps, not
unsupported capabilities. The 0.4 candidate extends the existing typed
`Input`/`Parameter` contract; it does not create a second Value mechanism.

## Original source example

Representative source (`SV-224867`, Windows Server 2016):

```xml
<xccdf:Value id="xccdf_mil.disa.stig_val_3" type="number" operator="less than or equal">
  <xccdf:title>Maximum allowed value</xccdf:title>
  <xccdf:value>3</xccdf:value>
</xccdf:Value>
<!-- selected OVAL check: -->
<xccdf:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5"
             selector="">
  <xccdf:check-export export-name="oval:...:var:3"
                     value-id="xccdf_mil.disa.stig_val_3"/>
</xccdf:check>
<!-- OVAL declaration: -->
<oval:external_variable id="oval:...:var:3" datatype="int"/>
```

The other four active source Values use `greater than or equal` or
`less than or equal` and OVAL `datatype="int"`; finite possible values are
also preserved when present. The source XML, IDs, check selection, and Value
hash are retained in each conversion warning.

## Native candidate

The existing organizational Input and Parameter carry the same typed relation:

```yaml
inputs:
  maximum-allowed-value-input:
    datatype: integer
    cardinality: exactly_one
    required: true
    constraints:
      allowed: [3, 5, 10, 50]
      relation:
        operator: less_than_or_equal
        value: 3

parameters:
  maximum-allowed-value-parameter:
    id: maximum-allowed-value-parameter
    datatype: integer
    cardinality: one
    required: true
    resolution: publisher
    value: 3
    constraints:
      allowed: [3, 5, 10, 50]
      relation:
        operator: less_than_or_equal
        value: 3
```

The converter maps XCCDF operators as follows: `less than` → `less_than`,
`less than or equal` → `less_than_or_equal`, `greater than` → `greater_than`,
and `greater than or equal` → `greater_than_or_equal`.

## Contract and qualification

- Only integer and float Inputs may carry `relation`; bounds must already have
  the declared datatype. No lexical or Boolean coercion is performed.
- `allowed` and `relation` are conjunctive. Defaults and supplied values are
  validated; violating, missing, invalid, error, and unknown bindings remain
  explicit states and are never replaced.
- Inclusive and strict boundary vectors, allowed-plus-relation, bad datatype,
  Boolean, empty, missing, and error cases are covered by
  `tests/test_issue28_semantic_proof.py` and the Input presence tests.
- The five Rules move from blocked to automated converted/unproved in the
  candidate ledger. This is schema/compiler-adapter coverage, not independent
  OVAL/scanner equivalence proof.
