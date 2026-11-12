#!/usr/bin/env python3
"""Render the complete Issue #28 JSON ledger as a concise review table."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def cell(value):
    return str(value).replace('|', '\\|').replace('\n', ' ')


def render(report):
    scope = report['scope']
    classification = report['classification']
    lines = [
        '# Issue #28 complete conversion ledger', '',
        f"Source corpus: `{scope['source_revision']}`  ",
        f"Schema family: `{scope['schema_family_sha256']}`  ",
        f"Rules: **{scope['rules']}** across **{scope['benchmarks']}** benchmarks.", '',
        '## Mutually exclusive classification', '',
        '| Category | Rules |', '|---|---:|',
    ]
    for key, label in (
        ('automated_converted_proved', '`automated_converted_proved`'),
        ('automated_converted_unproved', '`automated_converted_unproved`'),
        ('manual_only', '`manual_only`'),
        ('genuinely_blocked', '`genuinely_blocked`'),
        ('intentionally_excluded', '`intentionally_excluded`'),
    ):
        lines.append(f"| {label} | {classification[key]} |")
    lines += ['', 'No Rules are independently proved by this authoring ledger.', '',
              '## Per-benchmark accounting', '',
              '| Benchmark | Source | Automated | Manual | Blocked | Excluded |',
              '|---|---:|---:|---:|---:|---:|']
    for row in report['benchmarks']:
        lines.append('| ' + ' | '.join(cell(row[key]) for key in (
            'filename', 'source_rules', 'automated_converted', 'manual_only',
            'blocked', 'intentionally_excluded')) + ' |')
    lines += ['', '## Primary blocker root causes', '',
              '| Category | Root cause | Rules | Representative source Rules |',
              '|---|---|---:|---|']
    for row in report['primary_blockers']:
        examples = ', '.join(cell(example['source_rule'])
                             for example in row.get('examples', []))
        lines.append('| ' + ' | '.join((cell(row['category']), cell(row['message']),
                                          cell(row['rules']), examples)) + ' |')
    lines += ['', '## Verification status', '',
              'The ledger was rebuilt from the pinned source ZIPs with SQLEXT-dependent '
              'SQL benchmarks intentionally excluded. Source Rule IDs, check selection, '
              'source hashes, raw blocker diagnostics, and provenance remain in '
              '`COMPLETE-LEDGER.json`. Aggregate blocker rows normalize generated '
              'filenames and AST payloads into root causes; no raw diagnostic is discarded.', '',
              'All automated Rules are **converted but unproved**; none is promoted by '
              'YAML/schema admission or compilation. This tools branch has no independent '
              'scanner/OVAL comparison or compiler qualification, so '
              '`automated_converted_proved` remains zero.']
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    report = json.loads(args.input.read_text(encoding='utf-8'))
    args.output.write_text(render(report), encoding='utf-8')


if __name__ == '__main__':
    main()
