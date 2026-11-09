#!/usr/bin/env python3
"""Rebuild the Issue #28 all-65 mutually-exclusive conversion ledger."""
from __future__ import annotations
from collections import Counter
from hashlib import sha256
import argparse, json, time
from pathlib import Path
from scap_ng_tools.converter.direct04 import convert_benchmark

EXPECTED_BENCHMARKS, EXPECTED_RULES = 65, 8892
SOURCE_REVISION = 'niwc-atlantic/scap-content-library@8c8e5dff860af6b1290ee9273a282db24278f8d5'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--schema-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    files = sorted(args.source_dir.glob('*.zip'))
    if len(files) != EXPECTED_BENCHMARKS:
        raise SystemExit(f'expected {EXPECTED_BENCHMARKS} source ZIPs, found {len(files)}')
    started = time.time(); totals = Counter(); benchmarks = []; root_causes = Counter(); examples = {}
    for number, source in enumerate(files, 1):
        source_hash = sha256(source.read_bytes()).hexdigest()
        _, trace, coverage = convert_benchmark(
            schema_root=args.schema_root, source=source, sha256_pin=source_hash,
            native_recovery=True, recover_manual=True, exclude_sqlext=True)
        statuses = Counter(row['status'] for row in coverage['rules'])
        for status, count in statuses.items(): totals[status] += count
        for row in coverage['rules']:
            if row['status'] == 'blocked':
                key = (row.get('primary_blocker', {}).get('category', 'unknown'),
                       row.get('primary_blocker', {}).get('message', 'unknown'))
                root_causes[key] += 1
                examples.setdefault(key, {'source_rule': row['source_rule'], 'title': row['title'],
                                          'benchmark': source.name})
        benchmarks.append({'filename': source.name, 'source_sha256': source_hash,
            'source_rules': coverage['summary']['source_rules'], 'statuses': dict(sorted(statuses.items())),
            'mode': coverage['mode'], 'sqlext_excluded': coverage['recovery']['excluded_sqlext'],
            'sqlext_nodes': coverage['recovery']['sqlext_nodes'],
            'coverage_digest': sha256(json.dumps(coverage, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'trace_digest': sha256(json.dumps(trace, sort_keys=True, separators=(',', ':')).encode()).hexdigest()})
        print(f'[{number}/{len(files)}] {source.name}: {dict(statuses)}', flush=True)
    if sum(item['source_rules'] for item in benchmarks) != EXPECTED_RULES:
        raise SystemExit('source Rule total does not match 8,892 baseline')
    accounted = sum(totals.values())
    if accounted != EXPECTED_RULES:
        raise SystemExit(f'statuses do not reconcile: {dict(totals)}')
    report = {'format': 'scap-ng-tools/issue28-conversion-ledger/1',
        'oval_version': '5.12.3', 'schema_version': '0.4.0', 'source_revision': SOURCE_REVISION,
        'scope': {'benchmarks': len(files), 'source_rules': EXPECTED_RULES,
                  'native_recovery': True, 'manual_recovery': True, 'exclude_sqlext': True,
                  'proof_boundary': 'Authoring/schema validation is not independent source proof or scanner execution.'},
        'totals': {'automated_converted': totals['converted'], 'manual_only': totals['manual'],
                   'excluded': totals['excluded'], 'blocked': totals['blocked'], 'all_rules': accounted},
        'root_causes': [{'category': category, 'message': message, 'rules': count,
                         'example': examples[(category, message)]}
                        for (category, message), count in root_causes.most_common()],
        'benchmarks': benchmarks, 'elapsed_seconds': round(time.time() - started, 3)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    lines = ['# Issue #28 complete conversion ledger', '',
        'Counts are mutually exclusive per source Rule. Converted entries are authoring/schema validated only.', '',
        '| Outcome | Rules |', '| --- | ---: |']
    for key in ('automated_converted', 'manual_only', 'excluded', 'blocked', 'all_rules'):
        lines.append(f"| {key} | {report['totals'][key]} |")
    lines += ['', '## Remaining blockers by primary root cause', '', '| Category | Diagnostic | Rules | Example |', '| --- | --- | ---: | --- |']
    for row in report['root_causes']:
        lines.append(f"| {row['category']} | {row['message'].replace('|', '\\|')} | {row['rules']} | {row['example']['benchmark']} / {row['example']['source_rule']} |")
    lines += ['', '## Benchmark status', '', '| Benchmark | Rules | Automated | Manual | Excluded | Blocked |', '| --- | ---: | ---: | ---: | ---: | ---: |']
    for row in report['benchmarks']:
        st = row['statuses']; lines.append(f"| {row['filename']} | {row['source_rules']} | {st.get('converted', 0)} | {st.get('manual', 0)} | {st.get('excluded', 0)} | {st.get('blocked', 0)} |")
    args.output.with_suffix('.md').write_text('\n'.join(lines) + '\n')
    print(json.dumps(report['totals'], sort_keys=True))

if __name__ == '__main__': main()
