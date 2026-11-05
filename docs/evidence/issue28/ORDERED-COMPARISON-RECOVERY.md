# Ordered comparison recovery

The prior `ordered comparison expansion requires integer source datatype`
diagnostic was too broad. The native schema already has a `float` datatype and
typed comparison vocabulary. The converter now wires the owner-coordinated
finite-expected binary32 contract through as an opt-in recovery candidate.

Representative source: Ubuntu 18.04 `SV-219237`:

```xml
<independent:shellcommand_state
    id="oval:navy.navwar.niwcatlantic.scc.linux:ste:21923701"
    version="16">
  <independent:exit_status datatype="int">0</independent:exit_status>
  <independent:subexpression
      datatype="float"
      operation="greater than or equal">10.0</independent:subexpression>
</independent:shellcommand_state>
```

This remains a converter/runtime recovery item, not a native language gap.
The converter handles exact decimal-to-binary32 expected-value conversion and
rejects nonfinite expected values per the contract. Ten primary Rules use this
path. Runtime collection/status propagation, compiler admission, scanner
execution, and source-result comparison remain unproved.
