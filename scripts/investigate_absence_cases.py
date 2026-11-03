#!/usr/bin/env python3
"""All eight pinned absence cases; syntax experiments are NOT source proofs."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import re

BASE = Path(__file__).resolve().parents[1]


def investigate(schema_root, source_root):
    from scap_ng_tools.contracts import FrozenSchemaSnapshot
    from scap_ng_tools.converter.direct04 import load_runtime
    from scap_ng_tools.converter.recovery04 import _classes, recover_benchmark
    from scap_ng_tools.converter._v04_semantic.validation import document_errors
    engine = load_runtime()
    from v04_direct_scap_source import digest, local_name, xml_identity
    Source, Visitor = _classes(engine)
    snapshot = FrozenSchemaSnapshot(schema_root)
    mappings = snapshot.supported_mappings(engine.CAPABILITIES)
    groups = defaultdict(list)
    for row in json.loads((BASE/'tests/fixtures/issue14-absence-pins.json').read_text()):
        groups[row['filename']].append(row)
    rows, source_nodes, probes = [], {}, []
    for filename, cases in sorted(groups.items()):
        pin, = {r['sha256'] for r in cases}
        model = Source(Path(source_root)/filename, pin, inventory_broken_references=True, draft_compatibility=True)
        docs, _, ledger = recover_benchmark(schema_root=schema_root, source=Path(source_root)/filename,
            sha256_pin=pin, rule_ids=[r['source_rule'] for r in cases])
        for old, current in zip(cases, ledger['rules']):
            rid = old['source_rule']; rule = model.rules[rid]
            if current['source_rule'] != rid or digest(xml_identity(rule)) != old['source_rule_sha256']:
                raise ValueError('original Rule identity mismatch')
            cid, did, _ = model.automated_check(rule); nodes, closure = model.nodes[cid], {}
            def walk(ident):
                if ident in closure: return
                n = nodes[ident]; h = digest(xml_identity(n))
                closure[ident] = {'qname': n.tag, 'parsed_node_sha256': h}; source_nodes[h] = xml_identity(n)
                for e in n.iter():
                    for k, v in e.attrib.items():
                        if k.endswith('_ref') and v in nodes: walk(v)
                    if local_name(e) in ('object_reference', 'filter') and (e.text or '').strip() in nodes:
                        walk(e.text.strip())
            walk(did)
            fields = []
            for ident in closure:
                if not local_name(nodes[ident]).endswith('_state'): continue
                for index, element in enumerate(nodes[ident]):
                    if element.get('check_existence') == 'none_exist':
                        fields.append({'parent': ident, 'child_index': index, 'parsed_node': xml_identity(element),
                            'parsed_node_sha256': digest(xml_identity(element)), 'attributes': dict(element.attrib),
                            'lexical_value': element.text})
            allowed = {f['parsed_node_sha256'] for f in fields}
            class SyntaxOnlyVisitor(Visitor):
                def predicate(self, element, mapping, selector=False, *, record_field=False):
                    if (not selector and not record_field and not len(element)
                            and digest(xml_identity(element)) in allowed
                            and dict(element.attrib) == {'check_existence': 'none_exist', 'operation': 'pattern match'}
                            and element.text == '.*'):
                        return {'values_found': 'none'}
                    return super().predicate(element, mapping, selector, record_field=record_field)
            count, diagnostic = 0, None
            try:
                experimental, _ = engine.convert_rule(model, rid, mappings, converter_factory=SyntaxOnlyVisitor)
                assessments = [d for d in experimental.values() if 'assessment' in d]
                errors = [e.message for d in assessments for e in document_errors(snapshot, 'assessment', d)]
                if errors: raise ValueError('; '.join(errors))
                for d in assessments: probes.append({'source_rule': rid, 'document': d})
                count = len(assessments)
            except ValueError as error: diagnostic = str(error)
            manual_id = re.search(r'SV-\d+', rid).group().lower() + '-manual-assessment'
            manual = next(d for d in docs.values() if d.get('assessment', {}).get('id') == manual_id)
            rows.append({'filename': filename, 'source_zip_sha256': pin, 'source_rule': rid,
                'source_rule_sha256': old['source_rule_sha256'], 'component': cid, 'definition': did,
                'closure': closure, 'absence_fields': fields, 'status_before': current['status'],
                'blockers_before': current['blockers'], 'manual_assessment': manual_id,
                'manual_document_sha256': digest(manual), 'manual_preserved': current['manual'],
                'syntax_probe_assessments': count, 'syntax_probe_diagnostic': diagnostic,
                'source_semantic_proof': False, 'scanner_execution': False})
    return {'format': 'issue14-absence-source-investigation/1',
        'source_commit': '8c8e5dff860af6b1290ee9273a282db24278f8d5', 'schema': snapshot.manifest(),
        'cases': rows, 'source_nodes': source_nodes,
        'qualification': 'Original pinned source inventory and explicitly unqualified syntax projections. No comparator removal is authorized by this experiment.'}, {
        'format': 'issue14-UNQUALIFIED-absence-syntax/1', 'production_admitted': False, 'assessments': probes}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--schema-root', required=True); p.add_argument('--source-root', required=True)
    p.add_argument('--output', type=Path, required=True); a = p.parse_args()
    if a.output.exists(): p.error('refusing existing output')
    report, probes = investigate(a.schema_root, a.source_root); a.output.mkdir(parents=True)
    for name, value in [('investigation.json', report), ('syntax-probes.json', probes)]:
        (a.output/name).write_text(json.dumps(value, indent=2)+'\n')
    print(json.dumps({'cases': len(report['cases']), 'absence_fields': sum(len(r['absence_fields']) for r in report['cases']),
                      'syntax_assessments': len(probes['assessments']), 'production_admitted': False}))


if __name__ == '__main__': main()
