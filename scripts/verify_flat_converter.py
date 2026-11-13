#!/usr/bin/env python3
"""External research-only converter equivalence probe for the flat 0.4 tree.

This is NOT a packaged converter. It imports an explicitly pinned legacy
checkout, runs the baseline there, then reruns with only the capability-map
loader substituted by scap-ng-tools' verified flat-schema contract. It never
modifies either checkout or source content, and requires no network access.
"""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

from scap_ng_tools.contracts.schema_snapshot_v041 import Pinned041SchemaSnapshot


def git_head(root):
    return subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root,
                                   text=True).strip()


def identity(document):
    return sha256(json.dumps(document, sort_keys=True,
                            ensure_ascii=False).encode('utf-8')).hexdigest()


def probe(args):
    original = args.converter_root.resolve(strict=True)
    if git_head(original) != args.converter_commit:
        raise ValueError('converter source HEAD differs from the requested pin')
    if not (original / 'tools/v04_direct_converter.py').is_file():
        raise ValueError('missing direct-0.4 converter in pinned source checkout')
    snapshot = Pinned041SchemaSnapshot(args.schema_root)
    zip_bytes = args.source_package.read_bytes()
    if sha256(zip_bytes).hexdigest() != args.source_sha256:
        raise ValueError('source fixture hash mismatch')
    if not args.rule or len(args.rule) != len(set(args.rule)):
        raise ValueError('select distinct pinned Rule IDs')

    sys.path.insert(0, str(original / 'tools'))
    import v04_direct_converter as legacy
    from v04_direct_scap_source import SourceModel
    from validate_native_json_schemas import build_validators, document_errors

    if legacy.ROOT.resolve() != original:
        raise ValueError('unintended legacy converter checkout was imported')
    baseline = SourceModel(args.source_package, args.source_sha256)
    before_docs, before_trace = legacy.convert(baseline, args.rule)
    mappings = snapshot.supported_mappings(legacy.CAPABILITIES)
    old_mappings = legacy.load_mappings()
    if mappings != old_mappings:
        raise ValueError('flat catalog changes accepted source converter mappings')

    loader = legacy.load_mappings
    try:
        legacy.load_mappings = lambda: mappings
        after_docs, after_trace = legacy.convert(
            SourceModel(args.source_package, args.source_sha256), args.rule)
    finally:
        legacy.load_mappings = loader
    if (before_docs, before_trace) != (after_docs, after_trace):
        raise ValueError('converted documents or source traces drift under flat schemas')

    validators = build_validators(snapshot.schema_root)
    findings = []
    for path, document in after_docs.items():
        for kind in document:
            for error in document_errors(validators[kind + '.schema.json'], document):
                findings.append(f'{path}: {error.message}')
    if findings:
        raise ValueError('flat schema rejected converted documents: ' + '; '.join(findings))
    native_digest = identity(after_docs)
    if args.expected_native_digest and native_digest != args.expected_native_digest:
        raise ValueError(f'native output hash changed: {native_digest}')
    return {
        'status': 'PASS_FOR_EXPLICITLY_SELECTED_SOURCE_RULES_ONLY',
        'converter_source_commit': args.converter_commit,
        'frozen_schema_sha256': snapshot.manifest()['aggregate_sha256'],
        'schema_layout': 'schema/',
        'source_zip_sha256': args.source_sha256,
        'rule_ids': args.rule,
        'capability_mappings': len(mappings),
        'native_document_count': len(after_docs),
        'native_document_sha256': native_digest,
        'baseline_equivalent': True,
        'flat_schema_validation_errors': 0,
        'qualifies_entire_converter': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--converter-root', type=Path, required=True)
    parser.add_argument('--converter-commit', required=True)
    parser.add_argument('--schema-root', type=Path, required=True)
    parser.add_argument('--source-package', type=Path, required=True)
    parser.add_argument('--source-sha256', required=True)
    parser.add_argument('--rule', action='append', required=True)
    parser.add_argument('--expected-native-digest')
    args = parser.parse_args()
    print(json.dumps(probe(args), indent=2))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(str(error))
