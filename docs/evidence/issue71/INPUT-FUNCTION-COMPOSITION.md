# 0.4.1 Input/function composition converter adapter

**Source witness:** `SV-221718` original signed Oracle Linux 7 Q3 V16, OVAL `def:518`.

- OVAL external Variable from XCCDF `check-export` stays a dynamic `{"input": "...-input"}` expression leaf; the XCCDF default is not substituted.
- OVAL local `int` Variables whose sole expression is `substring` are explicitly translated to `{"to_integer":{"substring":...}}` so subsequent arithmetic has a numeric typed operand. This recognizes *the specific source conversion boundary*, not a consumer-side cast.
- `to_integer` in the current canonical schema is a string-to-decimal conversion; invalid lexical strings or missing/incomplete Input must fail closed. Native Variable declarations still omit datatype.
- The original vendored OVAL visitor is not edited. The runtime adapter is installed in memory and acts only when `native_recovery=True`. The separate schema-change PR is [canonical #79](https://github.com/vanderpol/scap-ng/pull/79).

**No parity claim:** Tests in this PR confirm lowering/visitor-admission shape only. Full signed Rule admission requires the updated canonical schema and exact pack repin, RI Input binding evaluation/status propagation, original source outcome replay and no unrelated regressions.
