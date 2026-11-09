#!/usr/bin/env python3
"""Build a source-backed OVAL 5.12.3 feature coverage matrix for Issue #28."""
from __future__ import annotations
from collections import Counter, defaultdict
from hashlib import sha256
import argparse, json, zipfile
from pathlib import Path
import xml.etree.ElementTree as ET

from scap_ng_tools.converter.direct04 import load_runtime
_runtime = load_runtime()
OVAL, SourceModel, local_name, xml_identity, digest = (_runtime.OVAL, _runtime.SourceModel,
    _runtime.local_name, _runtime.xml_identity, _runtime.digest)
load_mappings, CAPABILITIES = _runtime.load_mappings, _runtime.CAPABILITIES
SourceInventory = __import__('v04_direct_inventory').SourceInventory

FUNCTIONS = {'concat', 'count', 'split', 'substring', 'regex_capture', 'unique', 'merge',
             'arithmetic', 'begin', 'end', 'cast'}
VARIABLES = {'constant_variable', 'external_variable', 'local_variable'}
FEATURES = {
    'filters': ('filter', 'supported by converter and native Set filter contracts; source-backed proof is separate'),
    'sets': ('set', 'supported by converter and native Set contracts; source-backed proof is separate'),
    'check_existence': ('check_existence', 'supported for approved native cardinalities; all_exist is opt-in recovery'),
    'entity_check': ('entity_check', 'supported where the capability mapping admits the operator'),
    'state_operator': ('state_operator', 'supported where the capability mapping admits the operator'),
    'check_operator': ('check', 'supported for bounded OVAL checks; complex-check remains unsupported'),
}


def feature_rows(source_dir, schema_root):
    from scap_ng_tools.contracts import FrozenSchemaSnapshot
    snapshot = FrozenSchemaSnapshot(schema_root)
    mappings = snapshot.supported_mappings(CAPABILITIES)
    mapping_names = {m['capability'] for m in mappings}
    counts = Counter(); benchmarks = defaultdict(set); examples = defaultdict(list)
    for path in sorted(Path(source_dir).glob('*.zip')):
        source = SourceModel(path, sha256(path.read_bytes()).hexdigest(), inventory_broken_references=True)
        inventory = SourceInventory(source, mappings=mappings)
        rows = inventory.rules()
        for row in rows:
            for node in row['dependencies']:
                tag = local_name(source.node(node['component'], node['id'], node['kind']))
                names = {tag}
                for construct in node['constructs']:
                    names.add(construct)
                found = set()
                for name in names:
                    if name in FUNCTIONS:
                        found.add(name)
                    if name in VARIABLES:
                        found.add(name)
                if tag.endswith('_test'):
                    capability = node.get('capability')
                    found.add('capability:' + (capability or tag))
                for name in names & {'filter', 'set'}:
                    found.add(name + ':operation')
                for name in found:
                    key = name
                    counts[key] += 1
                    benchmarks[key].add(path.name)
                    if len(examples[key]) < 3:
                        examples[key].append({'benchmark': path.name, 'rule': row['source_rule'], 'node': node['id']})
    rows = []
    for feature, count in sorted(counts.items()):
        if feature.startswith('capability:'):
            capability = feature.split(':', 1)[1]
            schema = 'supported' if capability in mapping_names else 'not admitted by snapshot'
            compiler = 'converter mapping present' if capability in CAPABILITIES else 'not enabled in direct converter'
            runtime = 'capability-specific runtime contract; independent scanner proof not established'
            status = 'supported-but-proof-gated' if capability in mapping_names else 'missing/unsupported'
        elif feature in FUNCTIONS:
            schema = 'active native grammar' if feature in {'concat', 'regex_capture', 'unique', 'merge'} else 'inactive broader function schema'
            compiler = 'implemented' if feature in {'concat', 'regex_capture', 'unique', 'merge'} else 'diagnostic blocker / no lowering'
            runtime = 'converter lowering only; independent OVAL parity not established'
            status = 'supported-but-proof-gated' if feature in {'concat', 'regex_capture', 'unique', 'merge'} else 'missing/unsupported'
        elif feature in VARIABLES:
            schema, compiler, runtime, status = ('active bounded Variable grammar', 'implemented for admitted forms',
                'source conversion and native authoring validation; runtime proof is separate', 'supported-but-proof-gated')
        else:
            schema, compiler, runtime, status = ('active 0.4 contract where capability-specific',
                'implemented where mapping exists', 'independent source proof required', 'supported-but-proof-gated')
        rows.append({'feature': feature, 'source_occurrences': count,
                     'benchmarks': len(benchmarks[feature]), 'schema': schema,
                     'compiler': compiler, 'converter': compiler, 'runtime': runtime,
                     'proof': 'source-backed proof not established by conversion', 'classification': status,
                     'examples': examples[feature]})
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--schema-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    rows = feature_rows(args.source_dir, args.schema_root)
    report = {'format': 'scap-ng-tools/issue28-oval-feature-coverage/1',
              'oval_baseline': '5.12.3', 'schema_version': '0.4.0',
              'scope': {'benchmarks': len(list(args.source_dir.glob('*.zip'))),
                        'source_revision': 'niwc-atlantic/scap-content-library@8c8e5dff860af6b1290ee9273a282db24278f8d5'},
              'contract': 'Schema admission is not runtime equivalence or independent proof.',
              'features': rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    md = ['# OVAL 5.12.3 → SCAP-NG 0.4 feature coverage', '', report['contract'], '',
          '| Feature | Source occurrences | Benchmarks | Schema | Converter/runtime status | Proof |',
          '| --- | ---: | ---: | --- | --- | --- |']
    for row in rows:
        md.append('| `{}` | {} | {} | {} | {} | {} |'.format(row['feature'], row['source_occurrences'],
            row['benchmarks'], row['schema'], row['classification'], row['proof']))
    args.output.with_suffix('.md').write_text('\n'.join(md) + '\n')
    print(json.dumps({'features': len(rows), 'output': str(args.output)}))

if __name__ == '__main__':
    main()
