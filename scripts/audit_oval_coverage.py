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
OVAL_PREFIX = '{' + OVAL
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

    DS = '{http://scap.nist.gov/schema/scap/source/1.2}'
    components = {}
    for component in root.findall(DS + 'component'):
        if component.get('id') and len(component) == 1:
            components[component.get('id')] = component[0]
    stream = root.find(DS + 'data-stream')
    refs = {} if stream is None else {
        ref.get('id'): ref.get('{http://www.w3.org/1999/xlink}href', '')[1:]
        for ref in stream.iter(DS + 'component-ref') if ref.get('id')
    }
    checklist = None if stream is None else stream.find(DS + 'checklists/' + DS + 'component-ref')
    benchmark_component = refs.get(checklist.get('id')) if checklist is not None else None
    benchmark = components.get(benchmark_component)
    rules = {rule.get('id'): rule for rule in (benchmark.iter(X + 'Rule') if benchmark is not None else ())
             if rule.get('id')}
    indexes = {component: {node.get('id'): node for node in value.iter() if node.get('id')}
               for component, value in components.items()}
    catalog = {}
    if stream is not None:
        for ref in stream.iter(DS + 'component-ref'):
            href = ref.get('{http://www.w3.org/1999/xlink}href', '')
            component = refs.get(ref.get('id'))
            if href.startswith('#'):
                catalog[href] = component
            # XCCDF check-content-ref uses the original component filename,
            # while the data-stream component-ref is prefixed with `cref_`.
            # Keep both aliases so selection inventory is provenance-exact.
            ref_id = ref.get('id', '')
            if '_cref_' in ref_id:
                catalog[ref_id.split('_cref_', 1)[1]] = component

    rows = defaultdict(lambda: {'occurrences': 0, 'rules': set(), 'attributes': set(),
                                'values': defaultdict(int), 'examples': []})

    def add(node, rule_id):
        if not node.tag.startswith(OVAL_PREFIX):
            return
        name = lname(node); item = rows[name]
        item['occurrences'] += 1; item['rules'].add(rule_id)
        item['attributes'].update(node.attrib)
        for key, value in node.attrib.items():
            item['values'][key + '=' + value] += 1
        if len(item['examples']) < 3:
            item['examples'].append(rule_id)

    def closure(component, identifier, rule_id, visited):
        key = component, identifier
        if key in visited:
            return
        visited.add(key)
        node = indexes.get(component, {}).get(identifier)
        if node is None:
            return
        add(node, rule_id)
        for descendant in node.iter():
            if descendant is not node:
                add(descendant, rule_id)
            for attribute, kind in (('definition_ref', 'definition'), ('test_ref', 'test'),
                                    ('object_ref', 'object'), ('state_ref', 'state'),
                                    ('var_ref', 'variable')):
                target = descendant.get(attribute)
                if target:
                    closure(component, target, rule_id, visited)
            if descendant.tag == O + 'object_reference':
                closure(component, (descendant.text or '').strip(), rule_id, visited)
            elif descendant.tag == O + 'filter':
                closure(component, (descendant.text or '').strip(), rule_id, visited)

    for rule_id, rule in rules.items():
        visited = set()
        for check in rule.findall('.//' + X + 'check'):
            for reference in check.findall(X + 'check-content-ref'):
                component = catalog.get(reference.get('href'))
                if component and reference.get('name'):
                    closure(component, reference.get('name'), rule_id, visited)

    result = []
    for name, item in sorted(rows.items()):
        result.append({'name': name, 'category': classify(name, None),
                       'occurrences': item['occurrences'], 'rules': len(item['rules']),
                       'attributes': sorted(item['attributes']),
                       'values': dict(sorted(item['values'].items())),
                       'representative_rules': sorted(set(item['examples']))})
    return {'filename': archive.name, 'source_sha256': sha256(raw).hexdigest(),
            'rules': len(rules), 'operations': result}


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
    benchmark_summary = [{
        'filename': report['filename'], 'source_sha256': report['source_sha256'],
        'rules': report['rules'],
        'operations': sorted(row['name'] for row in report['operations'])
    } for report in reports]
    result = {'format': 'scap-ng-tools/issue28-oval-source-inventory/1',
              'source_count': len(reports), 'rule_count': sum(r['rules'] for r in reports),
              'benchmarks': benchmark_summary, 'operations': operations,
              'qualification': 'Inventory only; no schema/runtime support inferred.'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'benchmarks': len(reports), 'rules': result['rule_count'],
                      'operations': len(operations)}, sort_keys=True))


if __name__ == '__main__':
    main()
