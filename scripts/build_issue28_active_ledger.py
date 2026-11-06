#!/usr/bin/env python3
"""Project a candidate all-65 audit into the active 63-benchmark ledger.

The source audit is intentionally run once over all 65 ZIPs so historical
provenance remains complete. This projection excludes only the owner-directed
Windows Server 2012/2012 R2 benchmarks and never mutates the historical report.
"""
from __future__ import annotations
from collections import Counter
import argparse, gzip, json, io
from pathlib import Path

EXCLUDED_MARKER = 'Windows_2012_and_2012_R2'
RECOVERY_TARGETS = {
    'legacy_wmi': {'historical_blockers': 15, 'migration_candidates': 15, 'recovered': 1, 'remaining': 14},
    'xccdf_value_constraints': {'historical_blockers': 5, 'recovered': 5, 'remaining': 0},
}
FUNCTION_TARGETS = {
    'count': {'historical_blockers': 37, 'recovered': 36, 'remaining': 1},
    'multi_component_aggregation': {'historical_blockers': 30, 'recovered': 30, 'remaining': 0},
    'split': {'historical_blockers': 19, 'recovered': 15, 'remaining': 4},
    'arithmetic': {'historical_blockers': 3, 'recovered': 0, 'remaining': 3},
    'substring': {'historical_blockers': 1, 'recovered': 1, 'remaining': 0},
}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('source_report', type=Path)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--rules-output', type=Path)
    args = ap.parse_args()
    report = json.loads(args.source_report.read_text())
    rows = [r for r in report['benchmarks'] if EXCLUDED_MARKER not in r['filename']]
    excluded = [r for r in report['benchmarks'] if EXCLUDED_MARKER in r['filename']]
    rules = report.get('rules', [])
    active_rules = [r for r in rules if EXCLUDED_MARKER not in r.get('benchmark', '')]
    excluded_rules = [r for r in rules if EXCLUDED_MARKER in r.get('benchmark', '')]
    classification = Counter(r['status'] for r in active_rules)
    # The source report has explicit statuses; preserve the public ledger names.
    statuses = {
        'automated_converted_proved': 0,
        'automated_converted_unproved': classification.get('converted', 0),
        'manual_only': classification.get('manual_only', 0),
        'genuinely_blocked': classification.get('blocked', 0),
        'intentionally_excluded': sum(r['source_rules'] for r in rows if r['scope'] == 'intentionally_excluded_sqlext'),
    }
    # Recompute mutually-exclusive primary blockers from Rule rows, rather than
    # subtracting overlapping diagnostic counters in benchmark summaries.
    primary = Counter()
    for rule in active_rules:
        if rule.get('status') == 'blocked':
            p = rule.get('primary_blocker') or {}
            primary[p.get('message', 'missing')] += 1
    output = {
        'format': 'scap-ng-tools/issue28-active-rule-ledger/1',
        'source_report': str(args.source_report),
        'scope': {**report['scope'], 'benchmarks': len(rows), 'rules': sum(r['source_rules'] for r in rows),
                  'excluded_platforms': ['Windows Server 2012', 'Windows Server 2012 R2']},
        'historical_classification': report['classification'],
        'classification': statuses,
        'excluded_historical_scope': {
            'benchmarks': [r['filename'] for r in excluded],
            'rules': sum(r['source_rules'] for r in excluded),
            'classification': {
                'automated_converted_unproved': sum(r['automated_converted'] for r in excluded),
                'manual_only': sum(r['manual_only'] for r in excluded),
                'genuinely_blocked': sum(r['blocked'] for r in excluded),
                'intentionally_excluded': sum(r['intentionally_excluded'] for r in excluded),
            },
        },
        'recovery_targets': RECOVERY_TARGETS,
        'per_function_recovery': FUNCTION_TARGETS,
        'recovered_function_rules': sum(v['recovered'] for v in FUNCTION_TARGETS.values()),
        'remaining_function_rules': sum(v['remaining'] for v in FUNCTION_TARGETS.values()),
        'recovered_blocker_rules': sum(v['recovered'] for v in RECOVERY_TARGETS.values()),
        'remaining_recovery_rules': sum(v['remaining'] for v in RECOVERY_TARGETS.values()),
        'primary_blockers_active': [
            {'message': message, 'rules': count} for message, count in primary.most_common()
        ],
        'benchmarks': rows,
        'provenance': {
            'historical_source_report_retained': True,
            'original_rule_ids_retained': True,
            'independent_proof_claim': False,
            'compiler_scanner_equivalence_claim': False,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + '\n')
    if args.rules_output:
        payload = json.dumps({'format': 'scap-ng-tools/issue28-active-rule-records/1',
                              'scope': output['scope'], 'rules': active_rules},
                             separators=(',', ':')) + '\n'
        with args.rules_output.open('wb') as raw:
            with gzip.GzipFile(fileobj=raw, mode='wb', mtime=0) as fh:
                fh.write(payload.encode('utf-8'))
    print(json.dumps({'classification': statuses, 'recovered_function_rules': output['recovered_function_rules']}, sort_keys=True))

if __name__ == '__main__':
    main()
