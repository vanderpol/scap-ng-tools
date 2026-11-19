# Windows registry group-behavior follow-up

- Source correction: [Self-Assertion PR #11](https://github.com/OVAL-Community/SCAP-Self-Assertion/pull/11)
- Converter context: [Tools PR #84](https://github.com/vanderpol/scap-ng-tools/pull/84)
- Machine receipt: `windows-registry-group-deprecated-followup.json`

The source asserted deprecated `include_group` and `resolve_group` behaviors. PR #11 removes those tests and their now-unreferenced Objects/States without substituting semantics. The baseline is blocked by the deprecated attributes; the corrected source advances past that hold but still exposes the separate canonical traversal-schema hold for the two valid downward `max_depth` tests (`tst:1006` and `tst:680`). Runtime and independent equivalence are not claimed.
