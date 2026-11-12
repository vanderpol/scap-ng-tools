# Issue #5 fixture and build-input acquisition review

The portable converter does not ship the signed benchmark ZIPs or OVAL XSDs.
CI checks out exact revisions into temporary paths, verifies source ZIP
SHA-256 values, and removes those inputs with the runner. This record prevents
those inputs from being mistaken for Apache-2.0 files in the Tools wheel.

## NIWC signed benchmark fixtures

- Repository: <https://github.com/niwc-atlantic/scap-content-library>
- Revision: `8c8e5dff860af6b1290ee9273a282db24278f8d5`
- Paths: `Archive/2026_Q3/` (four ZIP files listed in `TEST-FIXTURE-PINS.md`)
- License text: <https://github.com/niwc-atlantic/scap-content-library/blob/8c8e5dff860af6b1290ee9273a282db24278f8d5/LICENSE.md>

The pinned `LICENSE.md` states that the relevant U.S. Government work is in
 the public domain under 17 U.S.C. §105, requests acknowledgement, and requires
notice for derivative or modified versions. The fixture ZIPs are therefore
used only as external regression inputs and are not redistributed in this
repository or package. The source SHA-256 and Git blob identities are pinned
in `TEST-FIXTURE-PINS.md`.

## OVAL build-time inputs

- Repository: <https://github.com/OVAL-Community/OVAL>
- Revision/tag: `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706` (`v5.12.3`)
- CI path consumed: `oval-schemas/`
- Public release documentation: <https://github.com/OVAL-Community/OVAL/releases/tag/v5.12.3>

The GitHub repository metadata reports no SPDX license and the pinned tree
contains no license or notice file. Its README identifies the schemas as the
authoritative OVAL 5.12.3 release, but that is not a redistribution grant.
Consequently this input is **build-time only** and the licensing/redistribution
gate remains open pending owner/legal review. The generated semantic pack is
already committed under the Tools project license only as a derived artifact;
no OVAL XSD is committed or shipped.

## Research source provenance

The copied runtime and build helper provenance is pinned to research commit
`d12a644f4607cdc9c9ada50e3a96d4fd0060c6d9`; the copied project-owned files are
covered by the Tools license and their byte hashes are enforced by tests. The
original research checkout is not a runtime or CI dependency.

## Gate

Do not merge, publish, vendor OVAL XSDs, or claim redistribution rights until
an owner/legal review records the OVAL license decision. Updating this record
is not a substitute for that decision.
