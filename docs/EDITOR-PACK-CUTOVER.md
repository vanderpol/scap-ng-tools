# Frozen 0.4 offline editor-pack export: flat-schema qualification

This is a **build-time compatibility tool**, not the VS Code extension or an
editor release. It reproduces all prior editor schema resources from the
accepted, flattened 0.4 schema tree. It does **not** regenerate content,
change a normative JSON Schema, qualify scanner providers or authorize the
owner-controlled repository rename.

## Reproducible export

```sh
PYTHONPATH=src python scripts/build_v04_editor_metadata_pack.py \
  --schema-root /path/to/exact-scap-ng-staging-checkout \
  --oval-root /path/to/OVAL-v5.12.3-checkout \
  --source-commit ed4a9dce01af6849bf4be146c7678ef7804051e4 \
  --output /path/to/a-new/metadata-pack
```

The schema checkout must be a clean, exact Git commit, with the frozen 0.4
143-file digest and flat `schema/` layout. The OVAL checkout must be the
official `OVAL-Community/OVAL` commit
`2f140ee5c5dd1ed9606fcd5afc301f6baeb48706` (tag `v5.12.3`).
Inputs are never fetched implicitly. The exporter refuses to overwrite an
existing destination and uses a temporary staging directory.

The output contains **235 immutable derived resources**:

| Resource category | Count |
| --- | ---: |
| Frozen root JSON Schemas | 34 |
| Generated native capability schemas | 100 |
| Reviewed 0.4 capability mappings | 100 |
| Editor authoring vocabulary | 1 |

Every resource file is **byte-for-byte identical** to the accepted original
research exporter at
`d12a644f4607cdc9c9ada50e3a96d4fd0060c6d9`. The exact 235 resource
descriptors, 100 capability identities, and vocabulary URI have a SHA-256
digest (over canonical sorted JSON) of
`faa1c81c01c34a212e33827e3628f9c355255c1030fa8aa8936cb9d28522c564`.
Any drift fails before a pack is written.

Only the **`sourceCommit` and derived `manifestSha256`** change to identify
the flat staging source. The verified staging profile is:

```json
{
  "schemaVersion": "0.4.0",
  "sourceCommit": "ed4a9dce01af6849bf4be146c7678ef7804051e4",
  "manifestSha256": "57c0ce0695f84e188572bd5444156ceb577e3df7c80d580eaecf529e77bc3bc8"
}
```

CI checks the source commit, frozen schema snapshot, reviewed resource inventory,
the complete manifest digest, and each of the 235 raw resource hashes. The pack
remains an **unsigned local artifact** until a separate packaging/release step
is approved. It is **not** a scanner result or proof authority.

## Deferred and handoff conditions

- The historical `sqlext` SQL-extension XSD additions remain excluded; the
  owner identified unresolved host-versus-database/instance targeting that
  prevents automatically treating them as `sql512`. No alias is introduced.
- The existing VS Code metadata profile still names the historical research
  repository. Do **not** repoint or task the extension against this staging
  pin yet. First complete owner-controlled canonical repo cutover, then rebuild
  and publish an editor pack from the exact canonical source commit and update
  its profile in a reviewed editor PR. The stable versioned JSON `$id` URIs
  remain unchanged despite the flattened physical directory.
- The editor's proposed human-readable generated Test title, persistence of
  platform/capability test-data semantics, and authoring UI behavior are separate
  extension work; this exporter carries their frozen schema vocabulary without
  implementing UI behavior.
