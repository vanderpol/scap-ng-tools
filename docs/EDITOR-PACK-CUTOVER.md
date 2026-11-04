# Owner-amended 0.4 offline editor-pack export: flat-schema qualification

This is a **build-time compatibility tool**, not the VS Code extension or an
editor release. It packages the reviewed 0.4 schema candidate after the
2026-11-02 owner-approved pre-release `item_requirement` amendment. The
specification grammar changed; scanner/provider qualification did not.

## Reproducible export

```sh
PYTHONPATH=src python scripts/build_v04_editor_metadata_pack.py \
  --schema-root /path/to/exact-canonical-scap-ng-checkout \
  --oval-root /path/to/OVAL-v5.12.3-checkout \
  --source-commit 354c9c962c77488a3d939cab56f6ceecfd495d27 \
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

The original reviewed resource-identity hash was
`faa1c81c01c34a212e33827e3628f9c355255c1030fa8aa8936cb9d28522c564`.
The new **explicitly reviewed** schema/vocabulary identity is
`0297c8367f828123bcec8afe39d8a85712a51d938e3c918081eb9be41d75b562`.
The 100 capability-generated schemas and 100 mapping resources are unchanged;
the new authoring grammar and vocabulary are deliberately different. Any
unreviewed drift still fails before a pack is written.

The candidate's **`sourceCommit` and derived `manifestSha256`** are:

```json
{
  "schemaVersion": "0.4.0",
  "sourceCommit": "354c9c962c77488a3d939cab56f6ceecfd495d27",
  "manifestSha256": "1f981bcc09c294e15b287176482d6be0b0a9d3d128bda6c37a160826bda036e2"
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
- The canonical repository cutover is complete. Repin the VS Code editor to
  this schema-amendment commit **in coordination with the converter and sample
  fixture PRs**, and qualify CI before external Codex implementation tasking.
  Versioned JSON `$id` URIs remain the same; the amendment requires explicit
  re-review because a draft 0.4 source grammar has changed.
- The editor's proposed human-readable generated Test title, persistence of
  platform/capability test-data semantics, and authoring UI behavior are separate
  extension work; this exporter carries their frozen schema vocabulary without
  implementing UI behavior.

## Native discovery amendment candidate — 2026-11-02 (Issue #12)

The owner-approved [native Input discovery amendment](https://github.com/vanderpol/scap-ng/issues/8#issuecomment-6587857027)
uses canonical schema commit `6bccf83bdadf9c91ddb0f91769052bf318d1b32b`.
Its complete 143-file JSON family hash is
`dfbcb781008f62f41a547265da43fa5c32cce32bdd54438d0d6bd6093b62463e`.
Grouped Item requirements, 100 mappings and Result wire are preserved.

The 235-resource inventory has **one changed resource**, the Rule schema;
all other 234 resources are byte-identical to the preceding public pack.
[Resource comparison](NATIVE-INPUT-DISCOVERY-PACK.json) and
[code/schema provenance](NATIVE-INPUT-DISCOVERY-RECEIPT.json) preserve prior pins.
The new manifest SHA256 is
`d86423a0e097f494c080680702b1692cf4fd175d88a5e49de5fdaa0106461666`.

The pure derivation helper indexes value/presence references, skips explicit
literal payloads, and preserves real record members named like metadata or
expression operators. It is an index, not a substitute for semantic validation.
The existing presence checker now visits those real member predicates too;
optional consumption still requires positive guard dominance. No values or
runtime binding outcomes are invented. Source Rule maps may be omitted and
are compiled mechanically; explicit maps require complete semantic agreement.

Local qualification: 29 public tools tests PASS with all four pinned original
ZIPs, the exact schema and official OVAL checkout (no skipped tests). Original
535-Rule inventory/conversion goldens remain unchanged. Hosted CI receipts follow
this candidate; it is not a release or scanner qualification.
