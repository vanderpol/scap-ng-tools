#!/usr/bin/env python3
"""Produce the compact Issue #28 all-65 blocker ledger.

The input directory is an operator-provided checkout of the 65 signed Q3 2026
benchmark ZIPs. Source archives are never copied into the repository or into
the report. The converter remains the sole source of admission diagnostics.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import argparse
from hashlib import sha256
import json
from pathlib import Path
import re

from scap_ng_tools.converter.direct04 import convert_benchmark

EXPECTED_BENCHMARKS = 65
EXPECTED_RULES = 8892
SOURCE_REVISION = 'niwc-atlantic/scap-content-library@8c8e5dff860af6b1290ee9273a282db24278f8d5'
SCHEMA_COMMIT = '7354a24cdbfe18321153ccaef5d772801a10cd71'
SCHEMA_FAMILY = '63a61b3eb0ca95790721699f5e63b6f5a16b146660b9545a437519b508351db5'


def issue_key(problem):
    """Return a stable root-cause key without discarding raw Rule diagnostics.

    Converter diagnostics may contain generated filenames, native identifiers,
    object payloads, or complete function ASTs. Those details belong on the
    individual Rule trace; they must not create one ledger blocker category per
    generated document. Only the aggregate keys are normalized here.
    """
    category = problem.get('category', 'unknown')
    message = problem.get('message', 'unknown')
    if category == 'schema-semantic':
        if 'declared/derived datatype conflict' in message:
            return category, 'native Variable declared/derived datatype mismatch'
        match = re.search(r"['\"]name['\"]:\s*['\"]([^'\"]+)", message)
        if match and 'not valid under any of the given schemas' in message:
            return category, f'native function contract admission: {match.group(1)}'
        if "'traversal':" in message and 'not valid under any of the given schemas' in message:
            return category, 'native traversal contract admission'
        return category, 'native schema admission'
    return category, message


def compact(source_dir: Path, schema_root: Path, *, exclude_sqlext=True, native_recovery=True):
    sources = sorted(source_dir.glob('*.zip'))
    if len(sources) != EXPECTED_BENCHMARKS:
        raise ValueError(f'expected {EXPECTED_BENCHMARKS} benchmark ZIPs, found {len(sources)}')
    rows = []
    rule_rows = []
    primary = Counter()
    all_blockers = Counter()
    usage = defaultdict(Counter)
    examples = defaultdict(list)
    totals = Counter()
    for source in sources:
        source_hash = sha256(source.read_bytes()).hexdigest()
        excluded = exclude_sqlext and 'sql_server_' in source.name.lower()
        if excluded:
            # Inventory is still performed and retained; no SQL extension
            # capability is converted or replaced with an opaque equivalent.
            from scap_ng_tools.converter.direct04 import inventory_benchmark
            _, coverage = inventory_benchmark(schema_root=schema_root, source=source,
                                              sha256_pin=source_hash)
            for rule in coverage['rules']:
                rule['status'] = 'intentionally_excluded'
                rule['proof_level'] = 'none'
                rule['blockers'] = []
            summary = coverage['summary']
            summary['statuses'] = {'intentionally_excluded': summary['source_rules']}
        else:
            _, _, coverage = convert_benchmark(schema_root=schema_root, source=source,
                                               sha256_pin=source_hash,
                                               native_recovery=native_recovery)
            summary = coverage['summary']
        benchmark = {
            'filename': source.name,
            'source_sha256': source_hash,
            'source_rules': summary['source_rules'],
            'automated_converted': summary['statuses'].get('converted', 0),
            'manual_only': summary['statuses'].get('manual_only', 0),
            'blocked': summary['statuses'].get('blocked', 0),
            'intentionally_excluded': summary['statuses'].get('intentionally_excluded', 0),
            'primary_blockers': summary.get('rules_by_blocker_message', {}),
            'blocker_categories': summary.get('rules_by_blocker_category', {}),
            'scope': 'intentionally_excluded_sqlext' if excluded else 'in_scope',
        }
        # Retain the historical field for consumers of the PR #29 ledger.
        benchmark['converted'] = benchmark['automated_converted']
        rows.append(benchmark)
        for status, count in summary['statuses'].items():
            totals[status] += count
        rule_rows.extend(coverage['rules'])
        for rule in coverage['rules']:
            if rule['status'] != 'blocked':
                continue
            blockers = rule.get('blockers', [])
            if not blockers:
                blockers = [{'category': 'missing', 'message': 'no blocker diagnostic'}]
            primary[issue_key(blockers[0])] += 1
            for problem in blockers:
                all_blockers[issue_key(problem)] += 1
            for construct in rule.get('needed_constructs', []):
                usage[construct][rule['status']] += 1
            key = issue_key(blockers[0])
            if len(examples[key]) < 3:
                examples[key].append({
                    'benchmark': source.name,
                    'source_rule': rule['source_rule'],
                    'title': rule['title'],
                })
        for rule in coverage['rules']:
            for construct in rule.get('needed_constructs', []):
                usage[construct][rule['status']] += 1
    primary_rows = [
        {'category': category, 'message': message, 'rules': count,
         'examples': examples[(category, message)]}
        for (category, message), count in primary.most_common()
    ]
    all_rows = [
        {'category': category, 'message': message, 'rules': count}
        for (category, message), count in all_blockers.most_common()
    ]
    function_names = ('concat', 'regex_capture', 'unique', 'merge', 'count',
                      'split', 'substring', 'arithmetic', 'end', 'begin')
    variable_names = ('external_variable', 'local_variable', 'constant_variable')
    construct_rows = {}
    for name in (*variable_names, *function_names):
        construct_rows[name] = {
            'converted': usage[name].get('converted', 0),
            'blocked': usage[name].get('blocked', 0),
            'total': sum(usage[name].values()),
        }
    if sum(row['source_rules'] for row in rows) != EXPECTED_RULES:
        raise ValueError('source Rule total does not match the owner baseline')
    accounted = sum(totals.values())
    if accounted != EXPECTED_RULES:
        raise ValueError(f'Rule accounting changed: {dict(totals)}')
    feature_rules = defaultdict(set)
    primary_feature_rules = defaultdict(int)
    for rule in rule_rows:
        if rule.get('status') == 'intentionally_excluded':
            continue
        constructs = set(rule.get('needed_constructs', []))
        for key, names in {
            'access_token': {'accesstoken_test', 'accesstoken_object', 'accesstoken_state'},
            'legacy_wmi': {'wmi_test', 'wmi_object', 'wmi_state'},
            'wmi57': {'wmi57_test', 'wmi57_object', 'wmi57_state'},
            'count': {'count'},
        }.items():
            if constructs & names:
                feature_rules[key].add(rule['source_rule'])
        if rule.get('status') != 'blocked':
            continue
        primary_problem = (rule.get('blockers') or [{}])[0]
        primary_message = primary_problem.get('message', '')
        if primary_message.startswith('unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}accesstoken'):
            primary_feature_rules['access_token'] += 1
        if primary_message.startswith('unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}wmi_test'):
            primary_feature_rules['legacy_wmi_test'] += 1
        if primary_message.startswith('unsupported object capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}wmi_object'):
            primary_feature_rules['legacy_wmi_object'] += 1
        if (primary_message == 'unsupported function: count' or
                issue_key(primary_problem) ==
                ('schema-semantic', 'native function contract admission: count')):
            primary_feature_rules['count'] += 1
    diagnostic_stats = {
        'deprecated_oval_tests': {
            'access_token': {'source_rules_nonexcluded': len(feature_rules['access_token']), 'primary_blocker_rules': primary_feature_rules['access_token']},
            'legacy_wmi': {'source_rules_nonexcluded': len(feature_rules['legacy_wmi']), 'primary_blocker_test_rules': primary_feature_rules['legacy_wmi_test'], 'primary_blocker_object_rules': primary_feature_rules['legacy_wmi_object']},
        },
        'wmi57_supported': {'source_rules_nonexcluded': len(feature_rules['wmi57'])},
        'count_function': {'source_rules_nonexcluded': len(feature_rules['count']), 'primary_blocker_rules': primary_feature_rules['count']},
    }
    return {
        'format': 'scap-ng-tools/issue28-blocker-audit/1',
        'scope': {
            'schema_commit': SCHEMA_COMMIT,
            'schema_family_sha256': SCHEMA_FAMILY,
            'source_revision': SOURCE_REVISION,
            'benchmarks': len(rows),
            'rules': sum(row['source_rules'] for row in rows),
            'ledger_access': 'public pinned Q3 2026 ZIPs; VM-private ledger was not used',
        },
        'baseline': {'converted': totals.get('converted', 0),
                     'manual_only': totals.get('manual_only', 0),
                     'blocked': totals.get('blocked', 0),
                     'intentionally_excluded': totals.get('intentionally_excluded', 0),
                     'total': accounted},
        'recovery_mode': 'native_recovery' if native_recovery else 'historical_default',
        'diagnostic_stats': diagnostic_stats,
        'classification': {
            'automated_converted_unproved': totals.get('converted', 0),
            'automated_converted_proved': 0,
            'manual_only': totals.get('manual_only', 0),
            'genuinely_blocked': totals.get('blocked', 0),
            'intentionally_excluded': totals.get('intentionally_excluded', 0),
            'proof_note': 'No Rules are independently proved by this authoring ledger.'},
        'primary_blockers': primary_rows,
        'all_blockers': all_rows,
        'variable_function_usage': construct_rows,
        'benchmarks': rows,
        'recovery_order': [
            {'root_cause': 'all_exist', 'primary_rules': primary[('unsupported-construct', 'unsupported Test existence: all_exist')],
             'reason': 'Current 0.4 item_requirement explicitly maps all_exist to one_or_more; no schema change is required.'},
            {'root_cause': 'non_oval_checks', 'primary_rules': primary[('unsupported-selection', 'unsupported competing non-OVAL check/selector')],
             'reason': 'Manual/OCIL choices require preserved manual Assessments, not fabricated automation.'},
            {'root_cause': 'check_import_export', 'primary_rules': primary[('unsupported-selection', 'OVAL check imports/exports unsupported')],
             'reason': 'Bounded native Input/Parameter adapter is the next semantic recovery candidate.'},
            {'root_cause': 'variables_and_functions',
             'primary_rules': sum(v for (c, m), v in primary.items() if c == 'unsupported-construct' and ('function' in m or 'Variable' in m or 'aggregation' in m)),
             'reason': 'Recover only source-backed forms already admitted by the 0.4 grammar; retain OVAL Cartesian/status/casting behavior.'},
            {'root_cause': 'capability_gaps',
             'primary_rules': sum(v for (c, _), v in primary.items() if c == 'unsupported-capability'),
             'reason': 'Requires separate capability contracts or owner-approved unsupported/manual treatment.'},
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--schema-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--include-sqlext', action='store_true',
                        help='retain SQLEXT-dependent SQL benchmarks in the blocked in-scope set')
    parser.add_argument('--historical-default', action='store_true',
                        help='disable owner-approved native all_exist/Input recovery')
    args = parser.parse_args()
    report = compact(args.source_dir, args.schema_root,
                     exclude_sqlext=not args.include_sqlext,
                     native_recovery=not args.historical_default)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps(report['baseline'], sort_keys=True))


if __name__ == '__main__':
    main()
