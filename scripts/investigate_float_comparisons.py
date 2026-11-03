#!/usr/bin/env python3
"""Read-only ten-case float investigation, NOT a converter admission path.

The private Visitor below is deliberately scoped to syntax experiments. Its
Assessments are never returned as recovered documents, Rules or qualified drafts.
No runtime precision is selected by these probes.
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re

BASE = Path(__file__).resolve().parents[1]
PINS = BASE / 'tests/fixtures/issue14-float-pins.json'


def investigate(schema_root, source_root, cases=None):
    from scap_ng_tools.contracts import FrozenSchemaSnapshot
    from scap_ng_tools.converter.direct04 import load_runtime
    from scap_ng_tools.converter.recovery04 import _classes, recover_benchmark
    from scap_ng_tools.converter._v04_semantic.validation import document_errors
    engine = load_runtime()
    from v04_direct_scap_source import digest, local_name, xml_identity
    Source, Visitor = _classes(engine)
    snapshot = FrozenSchemaSnapshot(schema_root)
    mappings = snapshot.supported_mappings(engine.CAPABILITIES)
    cases = json.loads(PINS.read_text()) if cases is None else cases
    groups = defaultdict(list)
    for row in cases:
        if Path(row['filename']).name != row['filename'] or not row['filename'].endswith('.zip'):
            raise ValueError('unsafe source filename')
        groups[row['filename']].append(row)
    rows, probes, source_nodes = [], [], {}
    for filename, selected in sorted(groups.items()):
        pins = {row['sha256'] for row in selected}
        ids = [row['source_rule'] for row in selected]
        if len(pins) != 1 or len(ids) != len(set(ids)):
            raise ValueError('inconsistent source pins or duplicate Rules')
        pin = pins.pop()
        path = Path(source_root) / filename
        model = Source(path, pin, inventory_broken_references=True, draft_compatibility=True)
        docs, _, ledger = recover_benchmark(schema_root=snapshot.schema_root, source=path,
                                            sha256_pin=pin, rule_ids=ids)
        for old, current in zip(selected, ledger['rules']):
            if current['source_rule'] != old['source_rule']:
                raise ValueError('production ledger Rule order mismatch')
            rule = model.rules[old['source_rule']]
            if digest(xml_identity(rule)) != old['source_rule_sha256']:
                raise ValueError('source Rule pin mismatch')
            manual_id = re.search(r'SV-\d+', old['source_rule']).group().lower() + '-manual-assessment'
            manual = next((d for d in docs.values() if d.get('assessment', {}).get('id') == manual_id), None)
            if (current['status'] != 'BLOCKED' or current['rule_emitted'] or not current['manual']
                    or manual is None or manual['assessment']['mode'] != 'manual'
                    or list(document_errors(snapshot, 'assessment', manual))):
                raise ValueError('production blocked/manual preservation invariant failed')
            component, definition, _ = model.automated_check(rule)
            nodes, visited = model.nodes[component], {}

            def walk(ident):
                if ident in visited:
                    return
                node = nodes[ident]
                identity = xml_identity(node)
                node_hash = digest(identity)
                visited[ident] = {'qname': node.tag, 'parsed_node_sha256': node_hash}
                source_nodes[node_hash] = identity
                for child in node.iter():
                    for key, value in child.attrib.items():
                        if key.endswith('_ref') and value in nodes:
                            walk(value)
                    if local_name(child) in ('filter', 'object_reference') and (child.text or '').strip() in nodes:
                        walk(child.text.strip())

            walk(definition)
            floats = []
            for ident in visited:
                for index, child in enumerate(nodes[ident]):
                    if child.get('datatype') == 'float':
                        floats.append({'parent': ident, 'child_index': index,
                            'parsed_node_sha256': digest(xml_identity(child)),
                            'attributes': dict(child.attrib), 'lexical_value': child.text,
                            'qname': child.tag})
            if floats != old['float_entities']:
                raise ValueError('float source witness mismatch')

            # Investigative syntax projection only. Exact original float nodes
            # are allowlisted; never cast them to integers, normalize operators,
            # modify XML, or expose this as an option to recovery04.
            allowed = {f['parsed_node_sha256']: f for f in floats}

            class SyntaxProbeVisitor(Visitor):
                def predicate(self, element, mapping, selector=False, *, record_field=False):
                    if element.get('datatype') != 'float':
                        return super().predicate(element, mapping, selector, record_field=record_field)
                    witness = allowed.get(digest(xml_identity(element)))
                    if (witness is None or selector or record_field or len(element)
                            or dict(element.attrib) != {'datatype': 'float', 'operation': 'greater than or equal'}
                            or element.text not in ('0', '10.0')):
                        raise ValueError('outside exact float syntax experiment')
                    # Both thresholds are exactly representable. This does NOT
                    # establish precision for the observed values or any runtime.
                    return {'float_greater_than_or_equal': float(element.text),
                            'values_found': 'one_or_more', 'values_matching': 'every'}

            projected, diagnostic = [], None
            try:
                experimental, _ = engine.convert_rule(model, old['source_rule'], mappings,
                                                       converter_factory=SyntaxProbeVisitor)
                projected = [d for d in experimental.values() if 'assessment' in d]
                errors = [error.message for doc in projected for error in document_errors(snapshot, 'assessment', doc)]
                if errors:
                    raise ValueError('; '.join(errors))
                probes.extend({'source_rule': old['source_rule'], 'document': doc} for doc in projected)
            except ValueError as error:
                diagnostic = str(error)
                projected = []
            rows.append({'filename': filename, 'source_zip_sha256': pin,
                'source_rule': old['source_rule'], 'source_rule_sha256': old['source_rule_sha256'],
                'component': component, 'definition': definition, 'closure': visited,
                'float_entities': floats, 'before_status': 'BLOCKED', 'after_status': current['status'],
                'blockers': current['blockers'], 'manual_preserved': current['manual'],
                'manual_assessment': manual_id, 'manual_document_sha256': digest(manual),
                'rule_emitted': current['rule_emitted'],
                'compiled': False, 'independent_source_proof': False, 'scanner_execution': False,
                'experimental_assessments': len(projected), 'experimental_diagnostic': diagnostic,
                'production_admitted': False})
    counts = dict(Counter(row['after_status'] for row in rows))
    report = {'format': 'issue14-float-investigation/1', 'source_commit': '8c8e5dff860af6b1290ee9273a282db24278f8d5',
        'schema': snapshot.manifest(), 'counts_before': {'BLOCKED': len(rows)}, 'counts_after': counts,
        'recovered': 0, 'rules': rows, 'source_nodes': source_nodes,
        'qualification': 'Source inventory and native syntax only; precision undecided. No production admission, source proof or scanner execution.'}
    return report, {'format': 'issue14-UNQUALIFIED-float-syntax-probes/1',
                    'production_admitted': False, 'assessments': probes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--schema-root', required=True)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('refusing existing output')
    report, probes = investigate(args.schema_root, args.source_root)
    args.output.mkdir(parents=True)
    for name, value in [('investigation.json', report), ('syntax-probes.json', probes)]:
        (args.output / name).write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')
    print(json.dumps({'before': report['counts_before'], 'after': report['counts_after'],
                      'syntax_probes': len(probes['assessments']), 'production_admitted': False}))


if __name__ == '__main__':
    main()
