# Ordered comparison recovery

The current `ordered comparison expansion requires integer source datatype`
diagnostic is too broad. The native schema already has a `float` datatype and
typed comparison vocabulary; the converter/runtime path does not yet wire the
float contract through.

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

This should be tracked as a converter/runtime recovery item, not a native
language gap. A faithful implementation needs the existing float precision
contract, including NaN/infinity handling, lexical conversion failures, and
comparison behavior. Ten primary Rules currently hit this path.
