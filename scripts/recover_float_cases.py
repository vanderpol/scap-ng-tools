#!/usr/bin/env python3
"""Explicit binary32 recovery of ten pinned cases; no proof/scanner promotion."""
import argparse
from collections import Counter, defaultdict
from hashlib import sha256
import json
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]


def recover_cases(schema_root, source_root):
    from scap_ng_tools.converter.recovery04 import recover_benchmark
    from scap_ng_tools.converter.binary32 import require_contract
    from scap_ng_tools.contracts import FrozenSchemaSnapshot
    snapshot = FrozenSchemaSnapshot(schema_root)
    contract = require_contract(snapshot.schema_root)
    pins = json.loads((BASE/'tests/fixtures/issue14-float-pins.json').read_text())
    previous = {row['source_rule']: row for row in json.loads(
        (BASE/'docs/evidence/issue14-floats/investigation.json').read_text())['rules']}
    groups = defaultdict(list)
    for pin in pins:
        groups[pin['filename']].append(pin)
    results, rows = [], []
    for filename, selected in sorted(groups.items()):
        source_pin, = {pin['sha256'] for pin in selected}
        docs, trace, ledger = recover_benchmark(schema_root=schema_root,
            source=Path(source_root)/filename, sha256_pin=source_pin,
            rule_ids=[pin['source_rule'] for pin in selected], binary32_comparisons=True)
        results.append({'filename': filename, 'documents': docs, 'ledger': ledger})
        for row, pin, binding in zip(ledger['rules'], selected, trace['rules']):
            if row['source_rule'] != pin['source_rule'] or row['source_rule_sha256'] != pin['source_rule_sha256']:
                raise ValueError('source Rule identity mismatch')
            old = previous[row['source_rule']]
            manual = next(d for d in docs.values() if d.get('assessment', {}).get('id') == old['manual_assessment'])
            digest = sha256(json.dumps(manual, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                                       allow_nan=False).encode()).hexdigest()
            if digest != old['manual_document_sha256']:
                raise ValueError('original manual Assessment changed')
            rows.append({'filename': filename, 'source_zip_sha256': source_pin,
                'source_rule': row['source_rule'], 'source_rule_sha256': row['source_rule_sha256'],
                'before_status': old['after_status'], 'after_status': row['status'],
                'blockers': row['blockers'], 'manual_preserved': row['manual'],
                'manual_document_sha256': digest, 'rule_emitted': row['rule_emitted'],
                'schema_validated': row['schema_validated'], 'semantic_validated': row['semantic_validated'],
                'binary32_warnings': [w for w in binding.get('conversion_warnings', [])
                                     if w['code'] == 'native_binary32_comparison_v1'],
                'compiled': False, 'independent_source_proof': False, 'scanner_execution': False})
    report = {'format': 'issue14-binary32-recovery/1', 'contract': contract,
        'source_commit': '8c8e5dff860af6b1290ee9273a282db24278f8d5',
        'counts_before': dict(Counter(row['before_status'] for row in rows)),
        'counts_after': dict(Counter(row['after_status'] for row in rows)),
        'recovered': sum(row['after_status'] == 'AUTOMATED_DRAFT' for row in rows), 'rules': rows,
        'qualification': 'Explicit current-contract native DRAFT recovery; independent compilation is a separate receipt. No original-source or scanner equivalence.'}
    return report, results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--schema-root', required=True)
    parser.add_argument('--source-root', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('refusing existing output')
    report, results = recover_cases(args.schema_root, args.source_root)
    args.output.mkdir(parents=True)
    (args.output/'recovery.json').write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    for index, result in enumerate(results):
        (args.output/f'documents-{index}.json').write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    print(json.dumps({'before': report['counts_before'], 'after': report['counts_after'], 'recovered': report['recovered']}))


if __name__ == '__main__':
    main()
