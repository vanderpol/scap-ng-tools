# Windows audit-policy deprecated field follow-up

- Source correction: [Self-Assertion PR #10](https://github.com/OVAL-Community/SCAP-Self-Assertion/pull/10)
- Converter context: [Tools PR #84](https://github.com/vanderpol/scap-ng-tools/pull/84)
- Machine receipt: `windows-audit-deprecated-field-followup.json`

The pinned source Definition `oval:org.mitre.oval.test:def:708` used the OVAL 5.12.3-deprecated `kerberos_ticket_events` State field. The OVAL schema marks it deprecated since 5.11, removes it in 6.0, and states that it has no known audit-event-policy mapping. PR #10 removes only that field, preserves the remaining 55 valid fields, and increments the Definition/State versions. Baseline conversion remains explicitly blocked; the corrected candidate converts schema-valid as `CONVERTED_UNVERIFIED`. Runtime and independent OVAL equivalence are not claimed.
