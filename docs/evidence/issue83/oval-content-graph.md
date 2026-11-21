# OVAL Self-Assertion source graph controls

This compact receipt extends the source-content inventory without assigning
expected or actual results. It records graph references and authored Boolean
controls for the pinned source, including Object/State components so Set and
Filter references are not lost when the Test row is inspected alone.

- Source: `OVAL-Community/SCAP-Self-Assertion`
- Commit: `e3538595c5083b9c34d937a81d319234df9bbfaa`
- Source root: `SCAP_1.4/OVAL_Test_Content`
- Receipt: `/tmp/tools-issue83-content-controls-final2-1795106772/oval-content-inventory.json`
- Receipt SHA-256: `f3b0b0fd1c94daf5e0f2f6495ab070d063b5051511d515d5b3ac85b4d05d1da5`

## Inventory

- 145 source documents: 144 loose XML plus 1 embedded XML member
- 168 Definitions, 803 Tests, 267 Variables
- 643 identified Object components, 611 identified State components
- References: 820 `object_ref`, 733 `state_ref`, 853 `test_ref`, 169
  `var_ref`, 17 filter State references and 10 Definition references
- Boolean controls: 803 `check`, 795 `check_existence`, 121 `var_check`,
  7 `state_operator`, 98 `negate` and 185 `operator` attributes

Every row retains source file/member hashes, source element hashes, source IDs,
source paths and original control values. These are authoring controls only;
source expectations, conversion, execution, and independent equivalence remain
separate qualification states.
