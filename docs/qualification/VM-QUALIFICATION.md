# Codex VM qualification procedure

Full converter, signed-benchmark, OVAL Self-Assertion, and cross-repository RI
qualification runs execute on the retained Codex VM while hosted Actions
allowance is exhausted. The VM uses the exact scripts formerly called by the
Actions workflows; this is a relocation of execution, not a relaxed gate.

## Immutable inputs and receipts

Use fresh output directories outside all checkouts and never overwrite an
existing receipt. Pin these inputs for the current #116 lane:

- canonical SCAP-NG: `2d983fcbd7b2367d567ca8ccc689a378d08905e4`
- RI candidate: `57ede7f5f9f84a434a1c419908d281b6a7e088aa`
- OVAL 5.12.3: `2f140ee5c5dd1ed9606fcd5afc301f6baeb48706`
- corrected Self-Assertion: `d91e6ba33841e3202dc27d3e0d469a7abd939b16`

Before each substantial batch:

```bash
df -BG /tmp
python3 "$RI/tools/disk_preflight.py" --mode full --path "$OUT" --path /tmp
```

Every receipt must include the exact command, exit code, input commit/SHA-256,
output-file SHA-256, toolchain version, and an explicit PASS/FAIL/HOLD. Do not
commit generated corpora or upload source content.

## P0 converter/RI/46-Definition lane

This is the unchanged local/Actions lane:

```bash
scripts/qualify_p0_041.sh \
  "$CANONICAL" "$OVAL" "$RI" "$SELF_ASSERTION" "$OUT"
status=$?
printf 'qualify_p0_041.sh exit=%s\n' "$status"
exit "$status"
```

The script preserves the 497-test/14-skip and 46-Definition source receipt
when successful. It fails closed on RI pin, schema pin, source identity,
converter, Go, race, vet, or semantic-gate errors.

## Complete signed 65-benchmark conversion

Run the same source-root and schema-root arguments as
`.github/workflows/issue59-full65-rebuild.yml`:

```bash
python scripts/rebuild_issue59_full65.py \
  --schema-root "$CANONICAL/schema" \
  --source-root "$SIGNED_SOURCE" \
  --canonical-schema-commit 2d983fcbd7b2367d567ca8ccc689a378d08905e4 \
  --schema-aggregate-sha256 dc650646a24e727e68de242027cca3058683accc531f07bf6ace217609755b24 \
  --output "$OUT/full65-source-rule-rebuild.json"
```

Then run the existing regression-triage, datatype-recovery and remaining-field
commands in that workflow without changing their arguments. Preserve all JSON,
CSV and summary exit codes and hashes.

## Full OVAL Self-Assertion conversion/parity

Use the exact corrected source and canonical schema commands from
`.github/workflows/oval-regenerate-full-content.yml`:

```bash
python3 scripts/convert_self_assertion_corpus.py \
  --corpus "$SELF_ASSERTION" \
  --schema-root "$CANONICAL" \
  --source-commit d91e6ba33841e3202dc27d3e0d469a7abd939b16 \
  --output "$OUT/self-assertion-current-candidate"
python3 scripts/audit_self_assertion_parity.py \
  --source-root "$SELF_ASSERTION/SCAP_1.4/OVAL_Test_Content" \
  --pack "$OUT/self-assertion-current-candidate" \
  --expected-xml 143 --expected-definitions 167 --expected-tests 799 \
  --output "$OUT/full-source-parity.json"
```

A source-accounted conversion is not runtime or independent OVAL equivalence.
Any parity or semantic hold remains recorded as a hold.

## Hosted workflow policy

The expensive workflows are now `workflow_dispatch` only: P0 canonical
qualification, full-65 rebuild, full OVAL parity/regeneration, and RI runtime
qualification. Lightweight authoring, schema handshake, source-witness,
mainline-stack and security-boundary checks remain PR-triggered. No required
check is disabled; branch protection/required-check configuration must treat
only those lightweight checks as hosted gates, while the VM receipt is the
mandatory expensive qualification evidence.
