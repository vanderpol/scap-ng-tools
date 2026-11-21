# Windows registry group-behavior follow-up

- Source correction: [Self-Assertion PR #11](https://github.com/OVAL-Community/SCAP-Self-Assertion/pull/11)
- Converter context: [Tools PR #84](https://github.com/vanderpol/scap-ng-tools/pull/84)
- Machine receipt: `windows-registry-group-deprecated-followup.json`

The source asserted deprecated `include_group` and `resolve_group` behaviors. PR #11 removes those tests and their now-unreferenced Objects/States without substituting semantics. The baseline is blocked by the deprecated attributes; the corrected source advances past that hold but still exposes the separate canonical traversal-schema hold for the two valid downward `max_depth` tests (`tst:1006` and `tst:680`). Runtime and independent equivalence are not claimed.

## Exact residual schema evidence

PR #11 leaves five nondeprecated Tests. The two valid downward-recursion cases are
source `tst:1006` / Object `obj:284` (Object identity SHA-256
`c0a66608dfc998e91586eb5607e31189ede24be7384bcabb0ef045c446b44ec`; Test
identity SHA-256 `6bc7684d5914e9baf675b68f872f8e658b7eb9f7900917f997d66af31e91db3b`)
and `tst:680` / Object `obj:785` (Object identity SHA-256
`83a68e99cb699edf30ffcb3da149ff222743d66bae61b3629ea2acffb1c31863`; Test
identity SHA-256 `e902921ec7b9d857c21695376cde6fa3580089e34881054e283f69b111ccc107`).
They require `recurse_direction="down"` with `max_depth=1` and `max_depth=-1`
(unlimited), respectively. The converter's attempted native candidates are
retained in the JSON receipt.

The pinned schema's
`native-selector.schema.json#/$defs/windows_regkeyeffectiverights_object/oneOf/1`
allows `hive`, `key`, and `trustee_sid` (plus generic capability/filter/set
members), but not `traversal`; its `additionalProperties: false` rejects the
otherwise documented mapping to `capability-common.schema.json#/$defs/hierarchy_traversal`.
This is a canonical representability gap, not a deprecated-source or converter
workaround opportunity. No traversal semantics were invented in Tools.
