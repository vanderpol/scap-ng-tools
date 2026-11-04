# Issue #14/#19 filesystem selector compatibility candidate

This tools change is the converter-side half of the owner-approved Candidate A
coordination. It does not modify the VS Code editor repository and does not
introduce aliases or rename native fields.

## Accepted pins

| Artifact | Value |
| --- | --- |
| SCAP-NG schema source commit | `5a13698933c88ca1e271d635b9bee39af75bc027` |
| Flat JSON / root / root-ref counts | `145 / 35 / 658` |
| Schema aggregate SHA-256 | `0a8c5a5840b5a17839db87decf034544286baf56383f52de71795862cca20593` |
| Semantic contract pack SHA-256 | `5e3aa7a017cbce86cb724679fd1a3ce15e1ff63def48f09b61a3f83f3484fb92` |
| Editor resource count | `236` |
| Editor manifest SHA-256 | `305dbd0b77729c69f3bc5d40232b0b3fbc5a32646310678f61ff2ae304831a5f` |

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
