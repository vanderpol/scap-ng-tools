# macOS keychain deprecated Object follow-up

- Source correction: [Self-Assertion PR #12](https://github.com/OVAL-Community/SCAP-Self-Assertion/pull/12)
- Converter context: [Tools PR #84](https://github.com/vanderpol/scap-ng-tools/pull/84)
- Machine receipt: `macos-keychain-deprecated-object-followup.json`

The source used the OVAL 5.12.3-deprecated `environmentvariable_object`. PR #12 replaces it with `environmentvariable58_object` and the schema-defined `xsi:nil=true` current-process PID, preserving the HOME selector and keychain variable expression. The baseline is blocked; the candidate converts schema-valid as `CONVERTED_UNVERIFIED`. Runtime/equivalence are not claimed.
