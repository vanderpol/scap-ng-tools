# SCAP-NG Tools

Development-stage, Apache-2.0-licensed tools intended to be shared by SCAP-NG
converters, authoring applications, and post-conversion normalization workflows.

## Current limited import

This first **copy-first** checkpoint includes two dependency-free, presentation-only
helpers copied byte-for-byte from the frozen 0.4 core repository:

- `scap_ng_tools.authoring.names`: reviewed STIG navigation names and source SV-ID
  filenames. These names are **not** native identities or proof authority.
- `scap_ng_tools.authoring.records`: read-only access to preserved original Rule
  records. This never manufactures Assessments or changes proof status.

The converter, compiler, full authoring library, semantic validators and schema
files **have not moved**. `scap-ng` remains their authoritative home until an
independent dependency and test qualification succeeds. This repository is not
yet a complete 0.4 converter release or standalone scanner.

Run the focused standard-library tests using:

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
```

See [migration provenance](docs/MIGRATION-PROVENANCE.md) for exact source hashes,
licensing boundaries and the gated next steps.

