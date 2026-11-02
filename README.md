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

The [direct 0.4 focused converter](docs/FOCUSED-CONVERTER-MIGRATION.md) is now
copied into this package as an independently installable, source-pinned runtime
for **explicitly selected Rule IDs**. It reads the separate frozen flat schema
snapshot and emits structural-valid native JSON/YAML and source traces without
the original research checkout. Unmigrated benchmark-wide **conversion**,
compile, verify and draft modes fail explicitly. It is not a complete converter
or proof release.

**Read-only full-benchmark inventory** is also available using `--inventory-only`
without `--rule`. It discovers every source Rule and blocker without admitting
conversion, generating native Assessments or claiming scanner evidence. Four
original ZIPs, covering 535 Rules, are pinned for manifest/source-trace parity
with the original implementation. See the
[fixture acceptance ledger](docs/TEST-FIXTURE-PINS.md).

An external-only [legacy conversion equivalence probe](scripts/verify_flat_converter.py)
also compares pinned old/new direct converter outputs when the original
source checkout is available. It remains diagnostic only.

The compiler, full authoring library, independent semantic validators, other
converter modes (including benchmark-wide **conversion**) and schema files
**have not moved**. The original development
repository remains the authority for those features until their dependency
closure and proof/test fixtures are qualified. This repository is not yet a
complete 0.4 converter release or standalone scanner.

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

The focused CLI uses an explicit local snapshot and source hash:

```sh
scapng-convert-v04 --schema-root /path/to/pinned-scap-ng \
  /path/to/original-scap14.zip --sha256 EXPECTED_SOURCE_SHA256 \
  --rule EXACT_XCCDF_RULE_ID --output /path/to/new-output-directory
```

This command requires the converter dependencies installed from this package;
it does not fetch schema files, SCAP input or scanner data over the network.

For a complete **inventory without conversion**:

```sh
scapng-convert-v04 --schema-root /path/to/pinned-scap-ng \
  /path/to/original-scap14.zip --sha256 EXPECTED_SOURCE_SHA256 \
  --inventory-only --output /path/to/new-inventory-directory
```

See [migration provenance](docs/MIGRATION-PROVENANCE.md) for exact source hashes,
licensing boundaries and the gated next steps.

