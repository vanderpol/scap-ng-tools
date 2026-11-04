# Issue #14/#19 filesystem selector compatibility candidate

This tools change is the converter-side half of the owner-approved Candidate A
coordination. It does not modify the VS Code editor repository and does not
introduce aliases or rename native fields.

## Accepted pins

| Artifact | Value |
| --- | --- |
| SCAP-NG schema source commit | `54bbd761aab78432b108e2090dc4a0f966f578ef` |
| Flat JSON / root / root-ref counts | `145 / 35 / 673` |
| Schema aggregate SHA-256 | `d2d8d59bcc722eacdba80342232f6d92d5bba812aab077753486268c3f74aa2d` |
| Semantic contract pack SHA-256 | `0f2de8d318ed5a8a102e51ffbcc09dedaac074a21b04dc86799b5e9f0b773114` |
| Editor resource count | `236` |
| Editor manifest SHA-256 | `69c3b454ad52d4fae69432cdeb295f6963f39e0415560c13c9b4ee2d8ce0a8d5` |

The semantic pack was regenerated from the pinned OVAL 5.12.3 XSD and compared
byte-for-byte with the committed pack. The editor pack was regenerated as a
local verification artifact only; VS Code integration remains out of scope.

## Native selector contract

The converter emits the established OVAL names:

* `filepath`: complete path including filename
* `path`: containing directory
* `filename`: filename component

This applies to all nine selectors across `unix.file`, `windows.file`, and
`windows.fileeffectiverights`. Source XML acquisition names such as
`full_path`, `directory`, and `name` remain source crosswalk vocabulary only;
they are not accepted native aliases.

The regression test exercises the actual `AssessmentConverter`, YAML
serialization round trip, Draft 2020-12 validation, regex mapping, explicit
case-insensitive comparison, `filesystem: all`, and nullable `filename`.
The synchronized validation evidence is recorded in
[`docs/evidence/issue22/validation.txt`](evidence/issue22/validation.txt). The
filesystem compatibility tests cover all nine selector contracts; the pinned
benchmark parity assertions intentionally remain historical until owner
approval of the separate migration proposal.

## Issue #22 golden audit

The pinned four-fixture audit is recorded in
[`docs/evidence/issue22/`](evidence/issue22/). It compares the previous
canonicalized output with the Candidate-A output field-by-field. All 11
historical parity assertions are representation/provenance-only; no source
Rule, Assessment, Test, capability, or provenance record was lost. Historical
hashes remain unchanged pending owner approval of the separate migration
proposal.

The generated selector overlay now also retains the already-defined OVAL
5.12.3 Set form and mapping-declared NTUSER collection parameters. This fixed
six temporary Windows admission losses without changing converter semantics.
