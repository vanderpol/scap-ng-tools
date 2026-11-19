# Focused Self-Assertion source-correction replay: PRs #20 and #21

This receipt replays the two latest upstream content corrections against the
production converter. It is not a full-corpus run and makes no runtime or
independent OVAL-equivalence claim.

## Results

- **PR #20 (IOS):** baseline `version_test` is correctly classified as a
  deprecated source construct. Candidate `version55_test` remains blocked as
  an unsupported canonical capability. Counts remain 11 Definitions / 16 Tests,
  with 10 / 12 converted and 1 / 4 blocked.
- **PR #21 (Junos):** the deprecated `xml_config_test` source file is removed.
  One Definition, Test and Object leave the source denominator by explicit
  content correction. No `junos.show` substitution was made.

The machine receipt records exact source hashes, IDs, converter/schema pins,
replay manifest hashes, diagnostics and dispositions.

## Reproduction

```text
PYTHONPATH=src .venv/bin/python scripts/convert_self_assertion_corpus.py \
  --corpus <PR20-source-checkout> \
  --schema-root /tmp/scap-ng-schema-5ee-1795112108 \
  --source-commit 34d471b20ecf110d19b04396645e891cfb772487 \
  --family ios --output <bounded-output>
```

Repeat with the immutable baseline file for the IOS comparison. PR #21 is a
source deletion and is verified from commit
`9e079baea4432b3babff5429ca726c281872de1f`; its baseline XML hash and removed
IDs are retained in the receipt.

Canonical schema and converter holds remain explicit; no deprecated behavior
was reintroduced.
