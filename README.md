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
locator** (`scap_ng_tools.contracts.FrozenSchemaSnapshot`). The historical
pre-selector checkpoint was 143 files/34 roots/242 references; the current
coordinated Issue #14/#19 candidate is pinned to 145 JSON files, 35 roots, 673
references and aggregate SHA-256
`d2d8d59bcc722eacdba80342232f6d92d5bba812aab077753486268c3f74aa2d`, under an
explicitly selected flat `schema/` directory.
No schema files or source corpus are vendored into this tool package.

The [direct 0.4 converter](docs/FOCUSED-CONVERTER-MIGRATION.md) is an
independently installable, source-pinned runtime for **explicit Rule IDs** and
**qualified automatic benchmark-wide authoring conversion**. Both use the
frozen flat schema snapshot and produce native JSON/YAML and source traces
without the original research checkout. Benchmark conversion also runs the
original 0.4 Object, comparison, Variable and Input semantic gates through a
pinned 52-capability offline contract pack. CI rebuilds it from the official
OVAL 5.12.3 tag and audited generator-helper copies, with frozen original
converter and CLI-byte goldens and no research-repository checkout.
Independent proof, compiler,
scanner execution and draft-admission modes remain unmigrated.

**Read-only full-benchmark inventory** is also available using `--inventory-only`
without `--rule`. It discovers every source Rule and blocker without admitting
conversion, generating native Assessments or claiming scanner evidence. Four
original ZIPs, covering 535 Rules, are pinned for manifest/source-trace parity
with the original implementation. See the
[fixture acceptance ledger](docs/TEST-FIXTURE-PINS.md).
The Issue #22 golden-parity audit and migration evidence is recorded in
[docs/evidence/issue22](docs/evidence/issue22). Historical goldens remain
unchanged pending owner approval.

An external-only [legacy conversion equivalence probe](scripts/verify_flat_converter.py)
also compares pinned old/new direct converter outputs when the original
source checkout is available. It remains diagnostic only.

The compiler, full authoring library, historical-version conversion,
independent source proof/verification, draft admission and schema files
**have not moved**. This repository is not yet a complete 0.4 converter
release or standalone scanner.

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

For **automated benchmark authoring conversion** with original blocked-Rule
diagnostics (not full Benchmark policy equivalence or independent proof):

```sh
scapng-convert-v04 --schema-root /path/to/pinned-scap-ng \
  /path/to/original-scap14.zip --sha256 EXPECTED_SOURCE_SHA256 \
  --all-rules --output /path/to/new-unverified-directory
```

On the four pinned acceptance ZIPs, original and portable outputs match exactly:
**535 source Rules, 380 admitted, 155 blocked, and 766 native documents**.
The other modes (`--compile`, `--verify`, `--draft`) still fail closed. The
signed source ZIPs and old OVAL XSD set are not bundled in the installed
converter; the 0.4-only semantic pack is generated and byte-audited in CI.
See the [generator independence audit](docs/GENERATOR-INDEPENDENCE.md) for
public-source inputs and the explicitly deferred `sqlext` targeting contracts.

The [offline editor-pack exporter](docs/EDITOR-PACK-CUTOVER.md) independently
derives all 236 pinned 0.4 editor resources (35 root schemas, 100 capability
fragments, 100 mappings, and the vocabulary) from the flat schema plus the
public official OVAL 5.12.3 source. All derived resource bytes match the
previous research exporter; only the explicit canonical source commit and
manifest pin change. This is a CI/build-time artifact, **not** a VS Code
extension release or authorization to retask the editor.

See [migration provenance](docs/MIGRATION-PROVENANCE.md) for exact source hashes,
licensing boundaries and the gated next steps.

