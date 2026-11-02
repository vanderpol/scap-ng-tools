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

The compatibility checkpoint also adds a **shared offline 0.4 schema snapshot
locator** (`scap_ng_tools.contracts.FrozenSchemaSnapshot`), which verifies the
exact 143-file frozen JSON digest, 34 roots, 242 references and 100 supported
capability mappings under an explicitly selected flat `schema/` directory.
No schema files or source corpus are vendored into this tool package.

An external-only [legacy conversion equivalence probe](scripts/verify_flat_converter.py)
can compare pinned direct-converter outputs with flat-schema outputs while the
original source checkout is still available. This is a **migration test, not
a redistributed converter or validation runtime**.

The converter, compiler, full authoring library, semantic validators and schema
files **have not moved**. The original development repository remains the
converter source of record until its dependency closure and proof/test fixtures
are reviewed. This repository is not yet a complete 0.4 converter release or
standalone scanner.

Run the focused standard-library tests using:

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
```

For a real frozen schema snapshot, explicitly select a local checkout:

```sh
SCAP_NG_SCHEMA_ROOT=/path/to/pinned-scap-ng \
  PYTHONPATH=src python -m unittest discover -s tests -v
```

See the [converter cutover gate](docs/CONVERTER-CUTOVER.md) for the exact
source-backed compatibility command and remaining repository-migration work.

See [migration provenance](docs/MIGRATION-PROVENANCE.md) for exact source hashes,
licensing boundaries and the gated next steps.

