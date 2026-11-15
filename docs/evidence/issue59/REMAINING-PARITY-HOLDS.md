# Standalone OVAL parity disposition after field-type qualification

Pins remain unchanged: SCAP-Self-Assertion
`e3538595c5083b9c34d937a81d319234df9bbfaa`, OVAL Community 5.12.3
`2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`, and SCAP-NG 0.4.1 schema
`aece827964c785be77b088c3c61255a2d07fd9a9` (aggregate
`578315d1e00bd39449ed597ed3d39555384276bd36198a54ca0b1e3c17e72829`).

The independent parity audit now resolves a native `values` expression only
from the exact canonical capability mapping for its Item field. A field with
more than one permitted datatype remains unresolved; no declaration-level
cast or source-datatype guess is accepted. With that gate, the two prior
collected-field holds are resolved:

- `oval:navy.navwar.niwcatlantic.scc.test:def:967`,
  `linux.selinuxboolean.current_status`, resolves to the mapped `boolean`
  field and preserves the source Object identity and `item_field`.
- `oval:org.mitre.oval.test:def:354`,
  `solaris.environmentvariable58`'s process `pid` component, resolves to the
  mapped `integer` field and preserves the source Object identity and
  `item_field`.

The current audit result is **104/168 Definitions and 579/803 Tests converted,
source-accounted, with zero converted-parity failures**. It reports exactly two
`source_invalid` findings under the no-implicit-cast source-parity contract,
not converter execution failures. The label does not claim that XML parsing
failed; it records a source Variable datatype/domain conflict that requires no
invented native cast:

| Definition | Variable | Source XML SHA-256 | Source reason | Disposition |
|---|---|---|---|------|
| `oval:org.mitre.oval.test:def:895` | `oval:org.mitre.oval.test:var:589` | `573351f7b8e8a685ec90596ba7d0d5f8842988c42fbd6e1a34cdc73dc38ec1f8` | The source `local_variable` declares `datatype="float"` while its arithmetic operands are three multi-valued integer Variables; the independently derived arithmetic domain is integer, not the declared float domain; the no-implicit-cast parity contract therefore cannot qualify this source Variable. | Preserve source-invalid hold; do not invent float coercion. |
| `oval:org.mitre.oval.test:def:270` | `oval:org.mitre.oval.test:var:540` | `bfde9f6411bf7b0d6b63fc2ef81cb9ecf801cf7df36fe96556ea47169c4bd308` | The source `local_variable` declares `datatype="int"` for a bare `literal_component` whose source type is not declared as an integer; the component's pinned default domain is string rather than the declared integer domain; the no-implicit-cast parity contract therefore cannot qualify this source Variable. | Preserve source-invalid hold; do not add an implicit cast. |

Exact audit command:

```text
PYTHONPATH=src:. .venv/bin/python scripts/audit_self_assertion_parity.py \
  --source-root <SCAP-Self-Assertion@e3538595>/SCAP_1.4/OVAL_Test_Content \
  --pack <standalone-pack> \
  --schema-root <scap-ng@aece8279>/schema \
  --expected-xml 144 --expected-definitions 168 --expected-tests 803 \
  --output <parity-receipt>
```

This is structural source parity only. It is not RI execution, SCC
qualification, scanner equivalence, or approval to reinterpret either
source-invalid Definition.
