# Schema/semantic-pack repin note

The candidate schema tree for this recovery is the canonical schema branch
`codex/issue28-variable-functions`, commit `e84a2b2` (`Recover OVAL variable
function schema contract`). Its flat-schema family digest is
`e6172862554adc5713c35241a6970c747559d7a4218636228b76fd422aed1845` (143 JSON
members). The prior immutable tools snapshot remains
`63a61b3eb0ca95790721699f5e63b6f5a16b146660b9545a437519b508351db5` until the
schema PR is owner-approved.

The generated capability semantic pack is unchanged by this variable-expression
schema edit. Tools and VS Code must be repinned to the approved canonical
schema commit together; no editor files are modified in this recovery. Until
that repin, generated recovery output is a candidate artifact and is not
claimed as a frozen 0.4.0 compiler/scanner equivalence result.
