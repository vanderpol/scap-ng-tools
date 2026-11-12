#!/usr/bin/env python3
"""Qualify Issue #48 function recovery on the exact regression/count targets.

This command intentionally does not run benchmark-wide conversion. It selects
the 55 immutable regression Rule instances plus every source Rule closure that
contains count, converts each Rule independently with native recovery, and
performs the exact pinned schema validation used by the focused converter.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import gzip
import hashlib
import json
from pathlib import Path

from scap_ng_tools.converter import convert_focused


def load(path):
    opener = gzip.open if path.suffix == '.gz' else open
    with opener(path, 'rt', encoding='utf-8') as stream:
        return json.load(stream)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--schema-root', type=Path, required=True)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--regression-report', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()

    regression = load(args.regression_report)
    targets = {(row['benchmark'], row['source_rule'], 'regression')
               for row in regression['regressions']}
    count_targets = set()
    inventory = load(args.inventory)
    for benchmark in inventory['benchmarks']:
        for variable in benchmark['variables']:
            if any(item['name'] == 'count' for item in variable.get('functions', [])):
                for source_rule in variable.get('rules', []):
                    key = (benchmark['filename'], source_rule, 'count')
                    count_targets.add(key)
                    targets.add(key)

    results = []
    for benchmark, source_rule, target_kind in sorted(targets):
        source = args.source_dir / benchmark
        row = {
            'benchmark': benchmark,
            'source_rule': source_rule,
            'target_kind': target_kind,
            'source_exists': source.is_file(),
        }
        if not source.is_file():
            row.update(status='blocked', error='source archive not found')
            results.append(row)
            continue
        source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
        row['source_sha256'] = source_sha256
        try:
            documents, trace = convert_focused(
                schema_root=args.schema_root, source=source,
                sha256_pin=source_sha256, rule_ids=[source_rule],
                native_recovery=True)
            row.update(status='converted', document_count=len(documents),
                       trace_rule_count=len(trace.get('rules', [])),
                       schema_validation='passed', runtime_equivalence=False)
        except Exception as error:  # targeted qualification records blockers, never hides them
            row.update(status='blocked', schema_validation='failed_or_not_admitted',
                       error_type=type(error).__name__, error=str(error),
                       runtime_equivalence=False)
        results.append(row)

    summary = {
        'target_instances': len(results),
        'regression_instances': sum(r['target_kind'] == 'regression' for r in results),
        'count_instances': len(count_targets),
        'converted': sum(r['status'] == 'converted' for r in results),
        'blocked': sum(r['status'] == 'blocked' for r in results),
        'regression_converted': sum(r['target_kind'] == 'regression' and r['status'] == 'converted' for r in results),
        'regression_blocked': sum(r['target_kind'] == 'regression' and r['status'] == 'blocked' for r in results),
        'count_converted': sum(r['target_kind'] == 'count' and r['status'] == 'converted' for r in results),
        'count_blocked': sum(r['target_kind'] == 'count' and r['status'] == 'blocked' for r in results),
    }
    report = {
        'format': 'scap-ng-tools/issue48-targeted-qualification/1',
        'scope': 'exact 55 regressions plus all source count-bearing Rule instances; no full-corpus generation',
        'pins': {
            'schema_commit': '63110e7762f4963d3e4d407e90b9fcfd9cfe86ad',
            'schema_family_sha256': '5d3b7f9507318c5ca2e85009fd8bc284d906d357b58cd278219c84f9481536a1',
            'source_commit': '8c8e5dff860af6b1290ee9273a282db24278f8d5',
        },
        'summary': summary,
        'results': results,
        'runtime_equivalence': False,
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'TARGETED-QUALIFICATION.json').write_text(
        json.dumps(report, indent=2, sort_keys=True) + '\n')
    lines = [
        '# Issue #48 targeted qualification', '',
        'Exact regression and count-bearing Rule conversion only; no full corpus was generated.', '',
        f"- Schema: `{report['pins']['schema_commit']}`; digest `{report['pins']['schema_family_sha256']}`",
        f"- Targets: {summary['target_instances']} ({summary['regression_instances']} regressions; {summary['count_instances']} count instances)",
        f"- Converted: {summary['converted']} / blocked: {summary['blocked']}",
        f"- Regression targets: {summary['regression_converted']} converted / {summary['regression_blocked']} blocked",
        f"- Count targets: {summary['count_converted']} converted / {summary['count_blocked']} blocked",
        '- Schema validation is structural qualification only; runtime/scanner equivalence is not claimed.', '',
        '## Remaining targeted blockers', '',
    ]
    for row in report['results']:
        if row['status'] == 'blocked':
            lines.append(f"- `{row['benchmark']}` `{row['source_rule']}` ({row['target_kind']}): {row.get('error', 'unknown blocker')}")
    (args.out / 'TARGETED-QUALIFICATION.md').write_text('\n'.join(lines) + '\n')
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
