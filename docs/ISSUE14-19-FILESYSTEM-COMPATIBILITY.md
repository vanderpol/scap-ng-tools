# Issue #14/#19 filesystem selector compatibility candidate

This tools change is the converter-side half of the owner-approved Candidate A
coordination. It does not modify the VS Code editor repository and does not
introduce aliases or rename native fields.

## Accepted pins

| Artifact | Value |
| --- | --- |
| SCAP-NG schema source commit | `7e38222494ee92a9a5584e2879d1688632bb21a5` |
| Flat JSON / root / root-ref counts | `145 / 35 / 658` |
| Schema aggregate SHA-256 | `e9405d79f9eac95e84a3f0293dcb37bd7f3e547b790131f296692baa656838a5` |
| Semantic contract pack SHA-256 | `212e9572c18e5fb25c53508531d1cb0d8c7b030d306d72b8a25d57db2645394d` |
| Editor resource count | `236` |
| Editor manifest SHA-256 | `e78ea28a779bf62c317582e3dd70f5e8c663fcde53c75098c2fb6bda9bf479dd` |

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
The tools suite with the accepted schema and pinned OVAL source completed with
20 passing tests and 3 fixture-dependent skips; the filesystem compatibility
tests covered all nine selector contracts.
