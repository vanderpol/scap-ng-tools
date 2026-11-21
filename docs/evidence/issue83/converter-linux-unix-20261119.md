# Current Linux/UNIX source-to-native conversion — 2026-11-19

This receipt replays the pinned Linux and UNIX Self-Assertion source through the production converter with the exact flat SCAP-NG 0.4.1 schema. It is authoring/schema evidence only; runtime and independent OVAL equivalence were not run.

## Results

- Definitions: **29**
- Tests: **134** (Linux 62, UNIX 72)
- Converted Definitions: **28**
- Converted Tests: **122**
- Schema-valid native YAML documents: **28**
- Blocked Definition: **1** (`unix/ind-def_textfilecontent54_test_unix.xml`, `def:48`)
- Blocked Tests: **12**
- Execution: not run

## Holds

- `def:48` and its dependent Tests are held by the exact deprecated `recurse_direction="up"` witness (`tst:466`, `obj:577`). The converter does not introduce upward recursion. Valid downward recursion remains a source correction/qualification path.
- UNIX SSHD `tst:483` is an explicit `unmapped_source_test` because the pinned baseline has its Definition criterion commented out; upstream PR #17 repairs the source.
- Linux source content is **62/62 converted**; no Linux converter blocker was observed in this replay.

Raw conversion artifacts remain external under the recorded `/tmp` root. The compact JSON receipt preserves exact pins, block IDs and artifact hashes.
