#!/usr/bin/env python3
"""Audit source and package-scoped applicability identity collisions.

This is an audit only: it never rewrites schema, source content, or archives.
Assessment/condition IDs are scoped to each benchmark package; reuse across
separate packages is expected and is reported separately from conflicts.
"""
from __future__ import annotations
import argparse, collections, gzip, hashlib, json, tarfile
from pathlib import Path
import xml.etree.ElementTree as ET

CPE = 'http://cpe.mitre.org/language/2.0'
XCCDF = 'http://checklists.nist.gov/xccdf/1.2'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def xml_identity(node):
    return [node.tag, sorted(node.attrib.items()), node.text if not len(node) else None,
            [xml_identity(child) for child in node]]


def source_paths(root, ledger):
    candidates = collections.defaultdict(list)
    for path in Path(root).rglob('*.zip'):
        candidates[path.name].append(path)
    result = {}
    for row in ledger['benchmarks']:
        matches = [p for p in candidates[row['filename']]
                   if hashlib.sha256(p.read_bytes()).hexdigest() == row['source_sha256']]
        if not matches:
            raise ValueError(f"source archive not found: {row['filename']}")
        result[row['filename']] = sorted(matches)[0]
    return result


def audit_source(root, ledger):
    ids = collections.defaultdict(list)
    global_ids = collections.defaultdict(list)
    benchmark_count = 0
    # SourceModel is deliberately used for the pinned SCAP input contract.
    from scap_ng_tools.converter.direct04 import load_runtime
    load_runtime()
    from v04_direct_scap_source import SourceModel
    for row in ledger['benchmarks']:
        path = source_paths(root, {'benchmarks': [row]})[row['filename']]
        source = SourceModel(path, row['source_sha256'])
        benchmark_count += 1
        for platform in source.root.iter(f'{{{CPE}}}platform'):
            identifier = platform.get('id')
            if identifier:
                entry = {'benchmark': row['filename'], 'source_xml_sha256': digest(xml_identity(platform))}
                ids[(row['filename'], identifier)].append(entry)
                global_ids[identifier].append(entry)
    duplicate_ids = {key: value for key, value in ids.items() if len(value) > 1}
    conflicting_ids = {key: value for key, value in duplicate_ids.items()
                       if len({item['source_xml_sha256'] for item in value}) > 1}
    return {
        'benchmarks': benchmark_count,
        'unique_cpe_platform_ids': len(global_ids),
        'duplicate_cpe_platform_ids': {key[1]: value for key, value in duplicate_ids.items()},
        'conflicting_cpe_platform_ids': {key[1]: value for key, value in conflicting_ids.items()},
        'cross_benchmark_cpe_platform_reuse': {key: value for key, value in global_ids.items() if len({item['benchmark'] for item in value}) > 1},
    }


def audit_archive(archive):
    packages = collections.defaultdict(lambda: {'conditions': {}, 'assessments': {}})
    with tarfile.open(archive, 'r:gz') as tar:
        for member in tar.getmembers():
            if not member.isfile() or not member.name.endswith('.json') or '/documents/' not in member.name:
                continue
            parts = Path(member.name).parts
            try:
                package = parts[parts.index('documents') + 1]
            except (ValueError, IndexError):
                continue
            document = json.load(tar.extractfile(member))
            bucket = packages[package]
            if 'applicability' in document:
                for condition_id, condition in document['applicability']['conditions'].items():
                    prior = bucket['conditions'].get(condition_id)
                    bucket['conditions'].setdefault(condition_id, {'path': member.name, 'value': condition})
                    if prior and prior['value'] != condition:
                        bucket.setdefault('condition_conflicts', {}).setdefault(condition_id, [prior]).append({'path': member.name, 'value': condition})
            if 'assessment' in document:
                aid = document['assessment'].get('id')
                prior = bucket['assessments'].get(aid)
                bucket['assessments'].setdefault(aid, {'path': member.name, 'value': document})
                if prior and prior['value'] != document:
                    bucket.setdefault('assessment_conflicts', {}).setdefault(aid, [prior]).append({'path': member.name, 'value': document})
    condition_conflicts = {p: b['condition_conflicts'] for p, b in packages.items() if b.get('condition_conflicts')}
    assessment_conflicts = {p: b['assessment_conflicts'] for p, b in packages.items() if b.get('assessment_conflicts')}
    condition_reuse = collections.Counter()
    assessment_reuse = collections.Counter()
    for bucket in packages.values():
        condition_reuse.update(bucket['conditions'].keys())
        assessment_reuse.update(bucket['assessments'].keys())
    return {
        'packages': len(packages),
        'condition_ids': sum(len(b['conditions']) for b in packages.values()),
        'assessment_ids': sum(len(b['assessments']) for b in packages.values()),
        'condition_conflicts': condition_conflicts,
        'assessment_conflicts': assessment_conflicts,
        'cross_package_condition_reuse': {k: v for k, v in condition_reuse.items() if v > 1},
        'cross_package_assessment_reuse': {k: v for k, v in assessment_reuse.items() if v > 1},
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--ledger', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    ledger = json.loads(args.ledger.read_text())
    report = {
        'format': 'scap-ng-applicability-collision-audit/1',
        'source': audit_source(args.source_root, ledger),
        'archive': audit_archive(args.archive),
    }
    report['status'] = 'PASS' if not report['source']['conflicting_cpe_platform_ids'] and not report['archive']['condition_conflicts'] and not report['archive']['assessment_conflicts'] else 'FAIL'
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': report['status'], 'output': str(args.output)}, sort_keys=True))
    if report['status'] != 'PASS':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
