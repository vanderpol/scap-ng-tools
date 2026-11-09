# SCAP-NG Tools Issue #27 VM report

## Stage A — automated 65-stream subset

**PARTIAL (usable, current-schema validated).** All 65 pinned source datastreams ran through the Issue #26 public converter at `c5f5b215000a1f9149ed56541320da5d7918c94a`, against schema `7354a24cdbfe18321153ccaef5d772801a10cd71`.

- Source revision: `niwc-atlantic/scap-content-library` `8c8e5dff860af6b1290ee9273a282db24278f8d5`
- 65/65 source ZIP SHA-256 and Git blob checks passed
- 8,892 source Rules; 4,524 converted; 4,368 blocked with explicit diagnostics
- 9,160 JSON + 9,160 YAML native documents validated against the current schema
- Second run: canonical semantic hashes matched 65/65; raw byte hashes differed only in one SQL Server 2016 Instance `coverage.json` because two equivalent schema blocker messages changed order
- Stage A output checksum root: `af9ae442c0f35ebceb424cc0c2bcb7dc81fc0dab9f270815034c617c32b0cb43`

## Stage B — complete source-preserving DRAFT library

**PASS WITH LIMITATIONS.** Six streams were qualified first, then all 65 were materialized locally.

- 8,892/8,892 source Rule XML records preserved
- 65/65 original source ZIPs retained and hash verified
- All source manual/OCIL, Profile, CPE/applicability, fix/remediation and publisher metadata remain available in the preserved original datastream records
- Current automated native subset remains schema-valid
- The native manual/policy/applicability translation gate is partial; no placeholder Assessments were fabricated
- Compile/package is blocked by the public tools boundary; proof and scanner runtime were not run
- DRAFT file checksum root: `b48cfe7dbfb71c79a62a437bcf084eb5b9cae61528f326fd7968214328dede61`

The historical October 30 full builder was run in an isolated copy for all six benchmark families. It compiled under its old schema, but all six failed current-schema validation due old `purpose`, overlong generated IDs, pre-amendment ungrouped `require.items_found`/`fields`, and historical variable/function shapes. It was not promoted or copied.

## Durable local paths

- Issue #26 receipts: `.external/issue26-receipts-20261105/`
- Library pointer: `.external/full65-current/README.md`
- Stage A: `.external/full65-current/automated-subset-7354a24cdbfe18321153ccaef5d772801a10cd71-20261105/`
- Stage B: `.external/full65-current/draft-source-preserving-7354a24cdbfe18321153ccaef5d772801a10cd71-20261105/`
- Reports/pipeline: `.external/full65-current/pipeline-issue27-20261105/`

Everything is ignored VM-local data; no generated corpus was added to Git, sample data, VSIX, or the graphical editor.
