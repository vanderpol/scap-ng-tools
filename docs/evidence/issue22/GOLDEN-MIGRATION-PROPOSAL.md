# Issue #22 golden migration proposal (owner review only)

This file belongs on a separate draft branch/PR from the converter and schema
correction. It updates only the expected parity hashes after the owner-approved
filesystem selector representation change; it does not alter source ZIPs,
converted content, provenance, or the historical audit report.

| Fixture | Native documents SHA-256 | Automatic trace SHA-256 | Inventory trace SHA-256 |
|---|---|---|---|
| Windows Server 2025 | `5687a4919b66e4e38e9d9dc2f59131393cf9683b0af768caf0ca4c3fa72deca8` | `28ccb0600d666f99b76b36164776a7b442276ef8282f614d87b28c470dcf95d4` | `0558217d6c90a39bf7f0e9b9bf8f8235f391df4152be639968ac1d3e132f41ff` |
| Active Directory Domain | `69d6606cf3b8c1e5ae943b5282ecf35a258556e5ce305b5ac1f4f9e1aa3bb10b` | `450aadbc110a26934a5688aefbed0c86e0e967ead6e1041cbc376e858f7dee64` | `a904fa7e88ff40bdea90825aac5d8b102a28fbd89d24b7c43b78aebe3b790824` |
| Amazon Linux 2023 | `7a9a7b578bf6f7f3498e58369f64340c719f7b50e5a376058974aefa20f6db4d` | `09d77b842843d3cab5b3dd4e9e28af253799ac3878608cd65239dc47a8d880e2` | `af1acfc9a2a7454153f629e2e1a88823f794bfa99e5cc4b4aef2cba980c7f4e1` |
| Windows Defender Firewall | `44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a` | `fde316371acb5b11e9f5b747b3138ec66e5ea07dc8609e6480543d2f0a7210bc` | `fde316371acb5b11e9f5b747b3138ec66e5ea07dc8609e6480543d2f0a7210bc` |

The owner-approved migration also changes the Amazon common CLI-byte digest
to `5fc696189a0e134077d46e46143e21b4b5637b635e43c12106b1d9b83509b3e5`.

Evidence: `benchmark-difference-report.json`, the before/after YAML pairs,
and `validation.txt` in this directory. The migration is representation-only;
merge requires explicit owner approval.
