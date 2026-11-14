#!/usr/bin/env python3
"""Build the individually-audited active Issue #28 blocker matrix.

The converter's per-Rule records are authoritative for source IDs, hashes,
selection, raw diagnostics, and provenance. This report adds a stable review
classification; it never drops raw blockers or promotes a Rule.
"""
from __future__ import annotations
import argparse, gzip, json
from pathlib import Path

WMI_RULES = {
    'xccdf_mil.disa.fso_rule_SV-225230r1117185_rule',
    'xccdf_mil.disa.fso_rule_SV-225232r1050651_rule',
    'xccdf_mil.disa.fso_rule_SV-225234r1188289_rule',
    'xccdf_mil.disa.fso_rule_SV-225235r960891_rule',
    'xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-259637r961608_rule',
    'xccdf_navy.navwar.niwcatlantic.scc.ms_rule_SV-259704r961608_rule',
    'xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218795r960963_rule',
    'xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218752r1111807_rule',
    'xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214416r879627_rule',
    'xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-214463r879643_rule',
    'xccdf_mil.disa.stig_rule_SV-224975r958524_rule',
    'xccdf_mil.disa.stig_rule_SV-205723r1137695_rule',
    'xccdf_mil.disa.stig_rule_SV-254396r1137695_rule',
    'xccdf_mil.disa.stig_rule_SV-278143r1182092_rule',
}
DATATYPE_RULES = {
    'xccdf_mil.disa.stig_rule_SV-274067r1120653_rule',
    'xccdf_mil.disa.stig_rule_SV-271596r1091500_rule',
    'xccdf_mil.disa.stig_rule_SV-258155r1045300_rule',
    'xccdf_mil.disa.stig.cisco_rule_SV-215833r961068_rule',
    'xccdf_navy.navwar.niwcatlantic.scc.ms.dns_rule_SV-220544r961068_rule',
    'xccdf_navy.navwar.niwcatlantic.scc.ms.dns_rule_SV-215688r961068_rule',
    'xccdf_navy.navwar.niwcatlantic.scc.ms.dns_rule_SV-220596r961068_rule',
    'xccdf_navy.navwar.niwcatlantic.scc.ms.iis_rule_SV-218771r1192784_rule',
}

def raw_problem(problem):
    return {key: problem[key] for key in
            ('category', 'component', 'message', 'source_id', 'source_path')
            if key in problem}

def classify(rule):
    rid = rule['source_rule']
    primary = rule.get('primary_blocker') or {}
    message = primary.get('message', '')
    if 'accesstoken_test' in message:
        return ('deprecated_accesstoken', 'intentionally_unsupported',
                'Owner decision: retain unsupported; do not fabricate userright equivalence.')
    if rid in DATATYPE_RULES:
        return ('variable_datatype_mismatch', 'deferred_0.5',
                'Retain explicit OVAL datatype; no inference or implicit cast in 0.4.')
    if rid in WMI_RULES:
        return ('legacy_wmi_record_projection', 'language_gap',
                'Native WMI returns records; 0.4 has no scalar record-member Variable projection.')
    if 'user_test' in message:
        return ('windows_user_capability', 'language_gap',
                'windows.user_sid cannot preserve user Object/State fields, filters, and password/group semantics.')
    if 'Variable source requires one var_ref' in message:
        return ('variable_source_set_filter', 'language_gap',
                'Variable-source Objects with Set/Filter populations are not admitted by the 0.4 Variable source contract.')
    if message == 'unsupported State field/namespace':
        return ('deprecated_rpm_state_field', 'intentionally_unsupported',
                'OVAL md5_differs is not the native filedigest_differs contract; no replacement fabricated.')
    if rid == 'xccdf_mil.disa.fso_rule_SV-225223r961038_rule':
        return ('registry_traversal', 'language_gap',
                'Exact-key/pattern-name downward traversal is not represented by the current Registry Object schema.')
    if 'nginx' in message:
        return ('nginx_cross_family_state', 'language_gap',
                'unix:file_test references independent shellcommand Object/State; requires an explicit cross-family contract.')
    if 'iis.' in message and 'state capability mismatch' in message:
        return ('iis_heterogeneous_set_filter', 'language_gap',
                'Existing Set filters require same-capability State references; source closure mixes IIS/appcmd/environment fields.')
    if 'native traversal contract admission' in message:
        return ('registry_traversal', 'language_gap',
                'Exact-key/pattern-name downward traversal is not represented by the current Registry Object schema.')
    if 'Variable cast outside bounded proof' in message:
        return ('variable_cast_boundary', 'deferred_0.5',
                'Declared and consumed datatypes disagree; explicit cast semantics require owner approval.')
    if 'Assessment Input function composition' in message:
        return ('input_function_composition', 'language_gap',
                '0.4 Inputs bind directly but are not operands in composed Variable expressions.')
    if 'function' in message or 'not one of' in message or "Native Variable expression" in message:
        return ('other_variable_or_function_boundary', 'deferred_or_audit',
                'Retain raw diagnostic; distinguish WMI record projection from the eight approved datatype cases.')
    raise ValueError(f'unclassified active blocker {rid}: {message}')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('rules', type=Path, help='ACTIVE-CANDIDATE-RULES.json.gz')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with gzip.open(args.rules, 'rt', encoding='utf-8') as stream:
        payload = json.load(stream)
    rows = []
    for rule in payload['rules']:
        if rule.get('status') != 'blocked':
            continue
        root, disposition, recommendation = classify(rule)
        rows.append({
            'source_rule': rule['source_rule'],
            'benchmark': rule['benchmark'],
            'title': rule['title'],
            'status': rule['status'],
            'proof_level': rule.get('proof_level'),
            'source': rule.get('source'),
            'checks': rule.get('checks', []),
            'primary_blocker': raw_problem(rule.get('primary_blocker', {})),
            'all_blockers': [raw_problem(item) for item in rule.get('blockers', [])],
            'needed_capabilities': rule.get('needed_capabilities', []),
            'needed_constructs': rule.get('needed_constructs', []),
            'root_cause': root,
            'disposition': disposition,
            'recommendation': recommendation,
        })
    rows.sort(key=lambda row: row['source_rule'])
    from collections import Counter
    counts = Counter(row['root_cause'] for row in rows)
    dispositions = Counter(row['disposition'] for row in rows)
    result = {
        'format': 'scap-ng-tools/issue28-blocker-matrix/1',
        'scope': payload['scope'],
        'qualification': {
            'individual_rule_rows': len(rows),
            'raw_provenance_retained': True,
            'independent_proof_claim': False,
            'compiler_scanner_equivalence_claim': False,
        },
        'counts_by_root_cause': dict(sorted(counts.items())),
        'counts_by_disposition': dict(sorted(dispositions.items())),
        'rules': rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'rules': len(rows), 'counts_by_root_cause': dict(counts)}, sort_keys=True))

if __name__ == '__main__':
    main()
