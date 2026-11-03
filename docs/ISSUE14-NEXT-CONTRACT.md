# Issue14 next contract boundary — 2026-11-03

The implemented [recovery milestone](ISSUE14-RECOVERY.md) and its review PR are
complete independently of this decision.38 historical automated blockers recover;
48 attempted blockers remain, plus336 explicitly held source/extension cases.
No current grammar, old proof or source data was changed to obtain those results.

## Concrete decision needed for further function recovery

Authorize a separate, coordinated pre-release0.4 native-function amendment for
**arithmetic, substring and split**, or retain the current closed grammar and
leave these11 first blockers deferred. This is not permission to activate the
entire13-function candidate or a claim that all11 Rules will become admitted:
a later source/mapping/semantics blocker may emerge after function support.

Current authority is explicit. The pinned
[active Variable schema](https://github.com/vanderpol/scap-ng/blob/d4e477998cda438a1e53a7c3c84123ec92e5ba1f/schema/variable-expression.schema.json)
is titled “Closed native Variable declarations and legacy expressions
(Decision29).” The separate
[canonical-call candidate](https://github.com/vanderpol/scap-ng/blob/d4e477998cda438a1e53a7c3c84123ec92e5ba1f/schema/variable-function-expression.schema.json)
says: “Inactive isolated canonical-call migration candidate; NOT referenced by
Assessment ... This candidate does not authorize native functions or runtime
support.” A converter-only bypass would therefore emit nonconforming authoring.
The Issue14 authorization permits repairs within approved language semantics,
not unilateral activation of that candidate.

## Pinned source evidence

- **Arithmetic:4 Rules.** Amazon Linux2023 SV-274067, Oracle Linux7 SV-221718,
  Oracle Linux9 SV-271596 and RHEL9 SV-258155. The RHEL9 exemplar multiplies
  dynamic Object fields `block_size` and `total_space`; replacing it with a
  literal or independently comparing either field would change the check.
- **Substring:5 Rules.** Exchange2019 Edge SV-259637/Mailbox SV-259704 and
  Windows Server2016 SV-224975/2019 SV-205723/2022 SV-254396. Real expressions
  consume dynamic Object fields, including start1/length1 and start3/length-1.
  They are not foldable static literals.
- **Split:2 Rules.** Solaris11 SPARC SV-216301 and x86 SV-216066. Accepting
  explicit default var_ref attributes reveals the dynamic split function; it
  does not resolve that deeper blocker. No string/list coercion was invented.

All source ZIP/Rule identities and present diagnostics are in the
[machine scoreboard](evidence/issue14/scoreboard.json). These source cases were
probed under the exact schema/tool pins in the recovery packet. No runtime
outcome or original semantic proof is asserted.

## Required boundary if authorized

Before implementation, review the exact active syntax and version treatment,
argument/result domains, multiplicity and Cartesian-product behavior, lexical
errors, empty/unknown/error/incomplete propagation and Object field semantics.
Coordinate schema, compiler/program and independent consumer, portable type and
source adapters, generated metadata and exact editor pins. Preserve legacy
forms, all frozen artifacts and their hashes; add bounded source-backed positive
and negative tests. Do not silently turn the inactive candidate into current
accepted design, infer source proofs from schema tests, or publish a new65 library.

Other remaining blockers are not hidden by this decision:10 ordered-datatype,
9 comparator-bearing absence,2 conflicting Value/OVAL operators,2 Value/Variable
datatype mismatches,3 invalid recursion cases and explicit capability/source
mismatches remain listed separately. Source corrections or additional normative
choices require their own evidence. No unsafe blanket coercion is authorized.
