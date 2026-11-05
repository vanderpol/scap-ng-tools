#!/usr/bin/env python3
"""Inventory OVAL language operations used by the pinned source corpus.

The scanner is intentionally read-only. It records names, attributes, source
hashes and representative Rule IDs; it does not infer support from XSD
acceptance. The companion matrix supplies the implementation/proof gates.
"""
from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
import argparse
import json
from pathlib import Path
import zipfile
import xml.etree.ElementTree as ET

OVAL = 'http://oval.mitre.org/XMLSchema/oval-definitions-5'
XCCDF = 'http://checklists.nist.gov/xccdf/1.2'
O = '{' + OVAL + '}'
X = '{' + XCCDF + '}'


def lname(node):
    return node.tag.rsplit('}', 1)[-1]


def classify(name, node):
    if name.endswith('_test'):
        return 'Test capability'
    if name.endswith('_object'):
        return 'Object capability'
    if name.endswith('_state'):
        return 'State capability'
    if name in {'filter', 'set', 'object_reference'}:
        return 'Object operation'
    if name in {'constant_variable', 'local_variable', 'external_variable',
                'variable_component', 'object_component', 'literal_component'}:
        return 'Variable construct'
    if name in {'concat', 'regex_capture', 'unique', 'merge', 'count', 'split',
                'substring', 'arithmetic', 'begin', 'end', 'escape_regex',
                'glob_to_regex', 'time_difference'}:
        return 'Function'
    if name in {'criterion', 'criteria', 'extend_definition'}:
        return 'Definition operator'
    return 'OVAL element'


def inventory(archive: Path):
    raw = archive.read_bytes()
    with zipfile.ZipFile(archive) as package:
        members = [name for name in package.namelist() if name.endswith('.xml')]
        if len(members) != 1:
            raise ValueError(f'{archive.name}: expected one XML member')
        root = ET.fromstring(package.read(members[0]))
    rows = defaultdict(lambda: {'occurrences': 0, 'rules': set(), 'attributes': set(),
                                'examples': []})
    rules_by_id = {rule.get('id'): rule for rule in root.iter(X + 'Rule') if rule.get('id')}
    for rule_id, rule in rules_by_id.items():
        # A dependency is attributed to a Rule by component-local reference
        # closure only in the converter. This source inventory intentionally
        # reports direct Rule descendants and all source nodes separately.
        for node in rule.iter():
            name = lname(node)
            if node.tag.startswith(O) or name in {'check', 'check-content-ref'}:
                key = name
                item = rows[key]
                item['occurrences'] += 1
                item['rules'].add(rule_id)
                item['attributes'].update(node.attrib)
                if len(item['examples']) < 3:
                    item['examples'].append(rule_id)
    for node in root.iter():
        if not node.tag.startswith(O):
            continue
        name = lname(node)
        # Function and capability names often occur only in the component,
        # outside the XCCDF Rule subtree. Keep their source-level counts.
        if name in rows:
            continue
        item = rows[name]
        item['occurrences'] += 1
        item['attributes'].update(node.attrib)
        if len(item['examples']) < 3:
            item['examples'].append(next(iter(rules_by_id), None))
    result = []
    for name, item in sorted(rows.items()):
        result.append({'name': name, 'category': classify(name, None),
                       'occurrences': item['occurrences'], 'rules': len(item['rules']),
                       'attributes': sorted(item['attributes']),
                       'representative_rules': sorted(x for x in item['examples'] if x)})
    return {'filename': archive.name, 'source_sha256': sha256(raw).hexdigest(),
            'rules': len(rules_by_id), 'operations': result}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--allow-fewer', action='store_true')
    args = parser.parse_args()
    sources = sorted(args.source_dir.glob('*.zip'))
    if not args.allow_fewer and len(sources) != 65:
        raise SystemExit(f'expected 65 source ZIPs, found {len(sources)}')
    reports = [inventory(source) for source in sources]
    merged = defaultdict(lambda: {'occurrences': 0, 'rules': 0, 'benchmarks': 0,
                                  'attributes': set(), 'examples': []})
    for report in reports:
        for row in report['operations']:
            target = merged[row['name']]
            target['occurrences'] += row['occurrences']
            target['rules'] += row['rules']
            target['benchmarks'] += 1
            target['attributes'].update(row['attributes'])
            target['examples'].extend(row['representative_rules'])
    matrix = json.loads((Path(__file__).parents[1] / 'docs/evidence/issue28/OVAL-COVERAGE-MATRIX.json').read_text())
    by_feature = {row['feature']: row for row in matrix['features']}
    operations = []
    for name, row in sorted(merged.items()):
        match = next((value for value in by_feature.values()
                      if value['feature'].split()[-1] == name or value['feature'] == name), None)
        operations.append({**row, 'name': name, 'attributes': sorted(row['attributes']),
                           'representative_rules': sorted(set(row['examples']))[:3],
                           'matrix_status': match['status'] if match else 'unclassified'})
    result = {'format': 'scap-ng-tools/issue28-oval-source-inventory/1',
              'source_count': len(reports), 'rule_count': sum(r['rules'] for r in reports),
              'benchmarks': reports, 'operations': operations,
              'qualification': 'Inventory only; no schema/runtime support inferred.'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'benchmarks': len(reports), 'rules': result['rule_count'],
                      'operations': len(operations)}, sort_keys=True))


if __name__ == '__main__':
    main()
