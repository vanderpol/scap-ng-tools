# RHEL9 check-text-first command cross-reference

**This pass found a promising native consolidation candidate and a broad
loaded-versus-persisted audit-rule alignment question.** It does not establish
that a shellcommand replacement is ready to implement.

The owner requested a second approach: start with simple commands in the DISA
check text, beginning with auditctl, and inspect the actual OVAL/native method.
All445 official RHEL9 V2R9 checks are now cross-referenced **without the earlier
complexity cutoff**. The scope remains415 converted automated Assessments;
27 manual-only and3 automated-without-native Rules are separately accounted for.
The [first audit](../rhel9-shellcommand/README.md) and every original artifact
remain unchanged at parent commit `14fd21039c026a4ef744c17cccc1f305040f42bb`.

## Main findings

1. **50 checks invoke `auditctl -l`;49 native Assessments instead inspect
   `/etc/audit/audit.rules`.** Those49 contain133 native Tests.31 already have
   only one Test;11 have two; the other seven have4,4,6,8,10,24,24 Tests.
   This is a collection-target distinction, not proof that either method is
   universally the correct policy. A valid file and the kernel's loaded rules
   can differ. Replacing the file reader with auditctl changes the evidence
   authority even when the regex conditions are preserved.
2. **One auditctl check is already a shellcommand Assessment:**
   `SV-279936r1210929` (cron audit rules). It retains four regex requirements.
   Its stdout framing and observed/expected-value quantifiers still need
   independent runtime tests before it can serve as a general template.
3. **All133 native regex presence requirements match the printed DISA examples**
   for their49 Rules, using both Python and GNU PCRE component execution.
   The command text may look short because a human must inspect all returned
   architectures, UIDs, syscall/path/permission conditions and keys. Merely
   finding a keyword is not the actual STIG decision.
4. **A same-file native consolidation is worth validating next:** the xattr
   family `SV-258179r1155601` can be expressed as one whole-file native Test with
   all24 original regex conditions kept independent. The original eight
   constant-string Variable expressions are folded without changing their raw
   regex bytes. Its authored-structure score is64 →10 (**84.38%**), with24 →1
   Tests and **24 →24 semantic regex obligations**. This is an unproved review
   sketch, not a production replacement or a claim of84% less semantic work.
5. **Other simple-command families mostly already have compact native methods.**
   All33 sysctl checks use a single native Test. There are19 sshd effective-query
   checks implemented through config-text parsing, and20 gsettings check texts
   (19 converted; seven already use shellcommand). Those are useful
   context/default/lock-policy alignment investigations, not automatically
   source-equivalent substitutions.

## Browse the cross-reference

- [Complete445-Rule CSV](crosswalk.csv): official commands, native Test count,
  score/capabilities, OVAL file selectors, existing commands and review tags.
- [50 auditctl-invocation Rules](auditctl.csv), including the existing cron
  shellcommand case. The four other auditctl mentions are tool filenames or
  AIDE output; they are not executions of auditctl.
- [Complete machine ledger](crosswalk.json): full official check text, command
  line offsets and lexical stages, source hashes/OVAL Object controls, exact
  native selectors/requirements/Variables/evaluate expressions, historical
  proof/program identities and source platforms. This lets a reviewer see what
  is actually checked, not just compare titles or utility names.
- [Audit regex comparison and two sketches](pattern-review/pattern-review.json).
- [Whole-file native sketch](pattern-review/case-same-file-native/proposed-UNAPPROVED.yaml)
  and [loaded-rule shell sketch](pattern-review/case-runtime-shell/proposed-UNAPPROVED.yaml).

### Representative actual comparisons

| Rule | DISA command / expectation | Actual converted method | Implication |
| --- | --- | --- | --- |
| SV-258176, execve | `auditctl -l \| grep execve`; four expected rules | Four regex-existence Tests on persistent audit.rules | Same printed examples, different collection authority; all four conditions matter |
| SV-258187, delete syscalls | `auditctl -l \| grep 'rename\|unlink\|rmdir'` | Ten persistent-file regex Tests, architecture/syscall/UID conditions | A short listing command does not remove ten obligations |
| SV-258179, xattr syscalls | `auditctl -l \| grep xattr` |24 persistent-file regex Tests plus eight literal-concat Variables | Promising scaffold/constant consolidation while retaining all24 checks |
| SV-279936, cron | `auditctl -l \| grep crond_t` | Already one shellcommand Test with four expected patterns | Existing use, not evidence that one keyword or quantifier ordering is sufficient |
| SV-258153, disk-error action | `grep disk_error_action /etc/audit/auditd.conf` | One text Test, case-insensitive capture, allowed SYSLOG/SINGLE/HALT comparisons | Already one native Test; preserve comments, duplicates and per-Item matching |
| SV-258229, immutable rules | `grep '^\s*[^#]' … \| tail -1` | One file regex locating `-e 2` at the end of the file | Comment/last-effective-line interpretation needs review; command pipeline is not automatically equivalent |
| SV-258137, AIDE audit tools | One grep, six expected tool paths and human fallback for other integrity mechanisms | Six presence-only regex Tests on aide.conf | Potential same-file consolidation, but not proof of every displayed hash attribute or human alternative |
| SV-258174, mail aliases | `postconf alias_maps`, then `postmap -q root …` | Already dynamic shellcommand: native Variable obtains map and builds query | The simple two-step utility approach is already represented |
| SV-258155, audit storage | grep log_file, inspect required storage | No converted Assessment in this pinned library; arithmetic blocker | Do not label source recovery or a simple replacement as completed |

## Scope counts and extraction limits

The pinned official manual and original NIWC source are the same inputs as the
first audit. All445 Rule bindings are exact; all445 manual/NIWC check texts agree
after whitespace normalization. Raw hashes remain available to distinguish that
comparison from byte identity. Each Rule and OVAL Object hash is checked against
the original ZIP; all415 native YAML identities and scores agree with the prior
inventory. No old proof label is upgraded.

The lexical index retains490 prompted records:486 recognized utility prompts,
three unclassified prompts and one configuration/empty record. Whitespace after
`$` or `#` is required, so `$Action…` rsyslog output is not mistaken for a command.
The three unclassified entries (FirewallBackend output, SELINUX explanatory text
and a dconf shell function) remain verbatim for manual review. This is a command
index, not an execution engine or complete shell parser. No extracted command is
executed. Utility recognition never establishes safety: for example, the manual
`logger` functional probe changes logging state and is explicitly flagged.

Counts below are Rules with the utility as a prompted command's first stage;
families overlap, so they must not be summed as a Rule denominator.

| Manual command family | Checks | Converted | Already has shellcommand | Converted with one native Test |
| --- | ---: | ---: | ---: | ---: |
| auditctl |50|50|1|32|
| sshd |19|19|0|12|
| sysctl |33|33|0|33|
| gsettings |20|19|7|13|
| systemctl |17|16|0|12|
| dnf |38|37|1|36|
| stat |45|44|0|43|
| grep |131|121|2|85|
| grubby |7|7|1|1|

There are21 converted Assessments with27 shellcommand collection sites, including
the indirect `postconf` acquisition used by a dynamic command. Their presence
does not newly approve enumeration, discovery or scripts in the retained source.
One Test can still have Variables, Sets or complicated matching; the full score
and executable structure are retained in the crosswalk.

## Two xattr review alternatives

**A — same-file native consolidation (recommended investigation first).** Keep
`independent.textfilecontent54` and the exact persistent file, capture its complete
text once, then evaluate24 independent regex predicates on that scalar text.
Source regex flags are explicit in each condition. Eight typed constant-string
concats are folded, with an original Test-to-regex hash mapping in the ledger.
All24 obligations remain; there is no Bash compliance decision, file discovery
or new external utility dependency. This is currently a **promising unproved
authoring consolidation**, not an accepted replacement.

The [unchanged original Assessment](../rhel9-shellcommand/case-10/original.yaml)
has547 YAML lines; the proposed same-file native copy has158. This removes
repeated authoring scaffolding while keeping the24 predicates visible.

**B — loaded-rule shell collection (conditional alignment sketch).** Run
`auditctl -l` once and keep24 independent native regex conditions plus explicit
exit-status evidence. This is not the earlier rejected one-keyword shortcut.
It has the same structural score10, but changes persistent-file authority to
loaded-kernel authority. It also conflicts with the original no-enumeration
criterion unless the owner explicitly allows this specific rule-list query.
Line framing, canonicalized auditctl output, multi-value matching, privilege and
error propagation remain unproved. It is **not implementation-authorized**.

Both sketches structurally validate at inspected canonical7354a24c. All source
snapshots and production content remain untouched. The scoring metric discounts
boilerplate and constant expression chains; it does not claim that the24 required
semantic checks became fewer. Human readability, logical-work estimates and full
equivalence must be reviewed independently of the84.38% structure score.

### Evidence and remaining proof

- 49 official printed-output fixtures /133 regex requirements: Python and GNU
  PCRE agree, all133 match. This is a real component experiment, not live auditctl
  output, an OVAL collector or a SCAP-NG scanner run.
- Six controlled complete-file snapshots cover positive, missing-b32 negative,
  empty, split-line malformed, duplicate and conflicting-extra-line input. All24
  original and proposed native regex results agree. The malformed split-line
  example is intentionally accepted by the original regex whitespace behavior;
  the audit does not silently repair that source behavior. Extra conflicting
  text is not silently changed from existential presence to an all-lines rule.
- Actual OS probes distinguish missing-file ENOENT from permission-denied EACCES.
  They do not prove native collector status conversion. Missing-file, permission,
  not-collected/unknown, incomplete collection and concurrent-snapshot behavior
  remain mandatory native runtime proof requirements.
- The whole-file native sketch must prove capture/field framing, regex flag and
  cardinality semantics, Item existence/error behavior and evidence adequacy in
  the actual compiler/consumer/scanner stack. Schema acceptance is insufficient.
- Rule Profiles, applicability, manual alternatives, source provenance and all
  historical proof identities must remain preserved in a later implementation.

## Owner decision packet for any auditctl adoption

The cross-reference alone does not authorize choosing between these policies:

1. **Preserve existing OVAL authority:** retain persistent-file semantics and
   validate alternative A. No data-authority exception is needed for a proven
   source-faithful consolidation under existing grammar.
2. **Follow the manual's loaded-rule procedure:** explicitly authorize bounded
   source corrections for selected Rules and an auditctl-list enumeration
   exception, then prove all original required conditions/statuses on pinned
   RHEL9 output. Keep the original method/provenance reproducible.
3. **Require both loaded and persistent rules:** a stricter policy requiring
   explicit owner authorization; it is not a lossless simplification or an
   automatic strengthening of the original Rule.

Recommendation: validate A first and review49 loaded-versus-persistent findings
as a separate alignment workstream. A promising lexical/authoring consolidation
does not settle scanner behavior; a manual-command match does not settle policy
authority. No replacement, normative contract change or compiler change is made
in this audit.

## Reproduce

Use the [original exact three input ZIPs](../rhel9-shellcommand/README.md#exact-scope-and-pin-qualification).
All output paths must be new. These scripts are read-only analyses and execute
no command taken from check text.

```sh
python scripts/cross_reference_rhel9_commands.py --archive /path/to/library.zip --source /path/to/pinned-RHEL9.zip --manual /path/to/official-DISA-V2R9.zip --output /tmp/rhel9-command-crosswalk
python scripts/review_rhel9_audit_patterns.py --crosswalk /tmp/rhel9-command-crosswalk/crosswalk.json --output /tmp/rhel9-audit-patterns
python scripts/validate_rhel9_audit_sketches.py --schema-root /path/to/canonical-at-7354a24c --review /tmp/rhel9-audit-patterns --output /tmp/rhel9-pattern-structure.json
PYTHONPATH=src python -m unittest discover -s tests -v
```

The component script requires GNU grep/PCRE on Linux; its only executable probes
are against synthetic text/temporary files. Native/RHEL9 scanner verification is
not supplied by it. Public CI needs no corpus or private toolchain download to
test the committed crosswalk and sketch identities. No full65 generation, source
repair, production Assessment modification, workflow edit, merge or release is
part of this continuation.
