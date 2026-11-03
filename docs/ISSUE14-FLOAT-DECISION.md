# Issue #14: ten original float comparisons — owner decision packet

2026-11-03. Based on tools PR #17, exact
`9a09d277f18feffa8975998231d931cd3edf4ce3`. **No production float recovery is
admitted by this investigation.** Existing typed syntax can express the operands
and operators; lossless observed-value conversion remains undecided. No schema,
runtime, Result, source-pin, manual-Assessment or historical-proof changes.

## Exact source inventory

All ten original Rules were reread from the nine signed ZIPs at NIWC commit
`8c8e5dff860af6b1290ee9273a282db24278f8d5`. Every entity below explicitly has
`datatype="float" operation="greater than or equal"`; none uses a Variable for
the expected value. No integer substitution is warranted by the lexical `0`.

| Original Benchmark | Exact Rule discriminator | Original value | Source acquisition |
| --- | --- | --- | --- |
| Ubuntu 18.04 V2R12 | SV-219237r958752 | `10.0` | audit storage |
| Ubuntu 20.04 V2R5 | SV-238305r958752 | `10.0` | audit storage |
| Ubuntu 22.04 V2R7 | SV-260595r958752 | `10.0` | audit storage |
| Ubuntu 24.04 V1R5 | SV-270816r1066937 | `10.0` | audit storage |
| Oracle Linux 8 V2R9 | SV-248811r958752 | `10.0` | audit storage |
| RHEL 8 V2R8 | SV-230476r958752 | `10.0` | audit storage |
| SLES 12 V3R5 | SV-217192r958752 | `10.0` | audit storage |
| SLES 12 V3R5 | SV-237605r1050789 | `0` | sudo timestamp timeout |
| SLES 15 V2R9 | SV-234965r958752 | `10.0` | audit storage |
| TOSS 4 V2R7 | SV-253031r958752 | `10.0` | audit storage |

[Exact input pins](../tests/fixtures/issue14-float-pins.json) include the full
archive names and ZIP SHA-256, Rule parsed-node hashes and float entity identities.
[The investigation ledger](evidence/issue14-floats/investigation.json) records
component/Definition IDs, every reachable Definition/Test/Object/State/Variable,
their parsed XML identities and digests, original attributes, manual-document
digests and current converter diagnostics. `object_reference` text inside Sets
and Filter references are traversed as well as reference attributes. Parsed-node
digests identify the converter's XML view; ZIP digests identify original bytes.
The old PR17 ledger is retained unchanged.

The nine audit Rules each reference two `shellcommand_object` patterns. A local
string Variable concatenates `df -h ` with the `subexpression` read from
`/etc/audit/auditd.conf` using `log_file\s+=\s+(\/\S+\/)+\S+\s*`. The two shell
patterns select size and available space respectively; both use
`(\d+(\.\d+)*)`, including **two capture groups**, and K/M/G/T/P suffixes.
No capture, shell command, unit handling, State exit-status test, cardinality or
Boolean relationship is repaired or simplified here. Typical `df -h` formatting
is not a pinned acquisition contract proving that all possible observed values
have a bounded precision. These source patterns also allow multi-dot numerals.

The SLES12 timeout State reaches a union of `/etc/sudoers` and recursive
`/etc/sudoers.d/` textfile Objects (maximum depth `-1`, recursion down,
`ignore_case=true`). Both use
`^[ \t]*Defaults[ \t]+timestamp_timeout[ \t]*=[ \t]*(-?[\d\.]+)`.
Negative arbitrarily small decimals and malformed numeric strings are in its
lexical capture domain. The full source controls remain in the ledger.

## Why existing syntax does not yet establish lossless conversion

The pinned official OVAL 5.12.3
[float declaration](https://github.com/OVAL-Community/OVAL/blob/2f140ee5c5dd1ed9606fcd5afc301f6baeb48706/oval-schemas/oval-common-schema.xsd)
defines IEEE single-precision **32-bit** values, including `INF`, `-INF`, `NaN`
and exponent notation. Its supported ordered comparison includes the exact
source operator used here.

At public canonical commit `246a8d37cc54875386768a7d76b60a6f9c01d013`,
`float_greater_than_or_equal` accepts JSON numbers. Both `10.0` and `0.0` are
exactly representable. However, [the specification entry point](https://github.com/vanderpol/scap-ng/blob/246a8d37cc54875386768a7d76b60a6f9c01d013/specification/README.md)
explicitly distinguishes schema structure from runtime behavior. No adopted
binary32 observed-value cast/rounding/nonfinite contract was found. The existing
strict converter's datatype module expressly defers float representation
fidelity. The unresolved [research issue #218](https://github.com/vanderpol/scap-ng-research/issues/218)
reserves the IEEE32/nonfinite design for owner review; it is not an approval.

The following independently specified boundaries show why a host binary64 cast
or "finite expected literals only" gate is insufficient:

| Source-shaped captured token | Binary32 comparison | Binary64 comparison |
| --- | --- | --- |
| `9.9999999` against `>= 10.0` | rounds to `10.0`, bits `41200000`: true | remains below 10: false |
| `-1e-46`, written as a decimal accepted by the timeout regex, against `>= 0` | underflows to negative zero, bits `80000000`: true | remains negative: false |

At 10, half an ULP is `2^-21`, greater than the exact distance `1e-7`; at zero,
`1e-46 < 2^-150`, half the smallest binary32 subnormal. Tests fix these bit
expectations independently of the host packing experiment and check the exact
source regexes. These are **comparison-boundary and lexical-domain witnesses**,
not actual `df` output, complete Rule counterexamples, independent OVAL evaluator
results or scanner equivalence. In particular the audit regex's second capture
must not disappear when reasoning about its source `entity_check=all` default.
Integer truncation is also invalid: `-0.5 >= 0` is false while `int(-0.5) >= 0`
is true. Malformed numerals must not become zero, null or absent fields.

## Concrete checks and before/after ledger

| Scope | PR17 before | After this investigation |
| --- | --- | --- |
| Selected float cases | 10 blocked / 0 recovered | **10 blocked / 0 recovered** |
| Real standalone manual Assessments for these cases | 10 | **10 preserved**, hashes recorded |
| Production automatic Rule projections for these cases | 0 | **0** |
| Entire selected 143-Rule recovery scope | 78 automated drafts / 20 manual / 45 blocked | unchanged |
| Historical automation blocker backlog | 381 | unchanged |

An **investigation-only** Visitor allowlists the original ten float nodes and
emits numeric float predicates into experimental complete Assessment closures.
It does not return converted Rules, production drafts or a recovery option.
All ten closures pass the existing public schema/type checks. Their original
default `one_or_more` field existence and `every` matching controls survive the
normal compact form; all other conversion paths remain strict.

Optional native checks at compiler commit
`7e26f8da44a81ae96135eca837e611a3f99f9c28` compile **10 experimental programs /
19 Tests**. The independent program reader confirms exact Assessment/program
operand and Boolean-plan identity; ten divergent-operand mutants are rejected.
[Compact receipt](evidence/issue14-floats/native-syntax-compilation.json).
This does not exercise float evaluation or establish original OVAL equivalence.
Production ledger `compiled`/source-proof/scanner flags remain false.

Portable tests cover all original source pins, exact ledger reproduction,
production rejection/manual retention, binary32 and binary64 boundary
differences, signed zero, positive/negative exact comparisons, integer coercion,
invalid numerals, overflow, nonfinite JSON serialization, accepted native typed
float predicates and rejected text/Boolean/null/conflicting datatype operands.
Full maintained-suite and preservation receipts are recorded in
[local-validation.json](evidence/issue14-floats/local-validation.json).
CI adds only the eight missing signed archives at the existing immutable NIWC
pin. No artifact uploads or quota retries are added.

Reproduce the source inventory and experimental syntax in a fresh directory:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python scripts/investigate_float_comparisons.py \
  --schema-root /path/to/exact-public-canonical \
  --source-root /path/to/pinned/Archive/2026_Q3 --output /tmp/fresh-float-investigation
```

For an explicitly available external toolchain, in a **fresh process**:

```sh
PYTHONDONTWRITEBYTECODE=1 python scripts/check_float_probe_compilation.py \
  --compiler-root /path/to/exact-toolchain \
  --compiler-commit 7e26f8da44a81ae96135eca837e611a3f99f9c28 \
  --probes /tmp/fresh-float-investigation/syntax-probes.json \
  --output /tmp/fresh-float-native-check.json
```

## Exact owner alternatives

1. **Recommended: coordinated binary32 semantic clarification for existing
   `float_*` syntax.** Specify conversion of both observed text and expected
   values, rounding, signed zero, subnormal/underflow/overflow, invalid lexical
   input and nonfinite observations/error propagation. Permit only exactly
   justified finite expected operands initially; retain explicit rejection of
   nonfinite expected literals until their JSON-safe representation is separately
   approved. Check acquisition/Result serialization implications too. Review
   canonical, native compiler/consumer and converter contracts together before
   admitting these source cases. This is a proposed normative interpretation,
   not a clarification already adopted by this PR.
2. **Defer all ten until the full IEEE32/nonfinite design in #218 is approved.**
   Broader coordinated representation work, with no immediate recovery.
3. **Choose binary64 or activate conversion merely because thresholds are
   finite/exact.** Reject for this lossless conversion task: the observed-value
   boundaries above remain unresolved. An explicit lossy policy would require a
   different product/compatibility decision and must not be called recovery.

Human decision: **pending**. This PR changes no language contract. Approval of
option 1 would authorize the subsequent coordinated design/implementation and
review, not assert that the ten cases are already recovered. Existing 0.3/0.4
Assessments and legacy proofs need explicit compatibility treatment if native
runtime meaning changes. No scanner-equivalence or release-readiness claim.
