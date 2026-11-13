#!/usr/bin/env python3
"""Audit-rebuild the 0.4 semantic pack from independently pinned public inputs.

This BUILD-TIME script uses the frozen flat SCAP-NG schema, the official OVAL
Community v5.12.3 tag, and an audited copy of the original 0.4 generator.
The installed converter still reads only its precompiled JSON contract pack.
No old research repository, XSD bundle, or network access is needed at runtime.
"""

import argparse
import json
from pathlib import Path
from hashlib import sha256
import subprocess
import sys
import tempfile

from scap_ng_tools.contracts.schema_snapshot_v041 import Pinned041SchemaSnapshot
from scap_ng_tools.converter.direct04 import load_runtime


OVAL_COMMIT = '2f140ee5c5dd1ed9606fcd5afc301f6baeb48706'
RESEARCH_GENERATOR_COMMIT = 'd12a644f4607cdc9c9ada50e3a96d4fd0060c6d9'
GENERATOR = Path(__file__).resolve().parent / '_v04_generation'


def git_head(path):
    return subprocess.check_output(
        ['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()


def build(schema_root, oval_root):
    snapshot = Pinned041SchemaSnapshot(schema_root)
    oval_root = Path(oval_root).resolve(strict=True)
    if git_head(oval_root) != OVAL_COMMIT:
        raise ValueError('official OVAL source is not the audited v5.12.3 commit')
    xsd_root = oval_root / 'oval-schemas'
    if len(list(xsd_root.glob('*.xsd'))) != 54:
        raise ValueError('incomplete OVAL v5.12.3 schema set')

    # Load audited converter modules before adding the generator-only module
    # search path; the runtime refuses mixed/foreign v04_* Python imports.
    runtime = load_runtime()
    sys.path.insert(0, str(GENERATOR))
    from generate_capability_schema_v04 import (  # noqa: E402
        generate, _generated_state_fields, _selector_fields,
    )
    import v04_direct_scalar_behaviors as behavior_source  # noqa: E402

    # These exact original generator helpers expect the former research folder
    # layout. Supply a throwaway path adapter without rewriting frozen inputs.
    with tempfile.TemporaryDirectory(prefix='scapng-v04-generator-overlay-') as temp:
        root = Path(temp)
        source_dir = root / 'third_party' / 'scap-1.4-schemas'
        source_dir.mkdir(parents=True)
        (source_dir / 'oval_5.12.3').symlink_to(xsd_root, target_is_directory=True)
        (root / 'schema').mkdir()
        (root / 'schema' / 'v0.4.1').symlink_to(
            snapshot.schema_root, target_is_directory=True)

        # This is a fresh build-only process. Restore and invalidate the
        # source lookup on exit; no installed converter behavior is changed.
        prior_root = behavior_source.ROOT
        behavior_source.ROOT = root
        behavior_source.original_attributes.cache_clear()
        try:
            capabilities = {}
            behaviors = {}
            for mapping in snapshot.supported_mappings(runtime.CAPABILITIES):
                source = mapping['source']
                fields, records = (_generated_state_fields(mapping, root)
                                   if source.get('state') else ({}, set()))
                capabilities[mapping['capability']] = {
                    'generated': generate(mapping, root, authoring_metadata=False),
                    'fields': fields,
                    'records': sorted(records),
                    'selectors': _selector_fields(mapping, root),
                }
                if behavior_source.behavior_routes(mapping):
                    key = source['definitions_schema'] + '::' + source['object']
                    behaviors[key] = behavior_source.original_attributes(
                        source['definitions_schema'], source['object'])
        finally:
            behavior_source.ROOT = prior_root
            behavior_source.original_attributes.cache_clear()

    body = {
        'format': 'scap-ng-portable-0.4.1-semantic-pack/1',
        'frozen_schema_digest': snapshot.manifest()['flat_json_aggregate_sha256'],
        # Historical derivation provenance, not a runtime or CI checkout.
        'schema_version': '0.4.1',
        'oval_commit': OVAL_COMMIT,
        'research_generator_commit': RESEARCH_GENERATOR_COMMIT,
        'generator_helper_sha256': {
            path.name: sha256(path.read_bytes()).hexdigest()
            for path in sorted(GENERATOR.glob('*.py'))
        },
        'capabilities': capabilities,
        'behavior_attributes': behaviors,
    }
    return json.dumps(body, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oval-root', type=Path, required=True)
    parser.add_argument('--schema-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raw = build(args.schema_root, args.oval_root)
    args.output.write_text(raw, encoding='utf-8')
    print(json.dumps({'capabilities': 52, 'bytes': len(raw.encode('utf-8')),
                      'source': 'official OVAL v5.12.3 + canonical flat 0.4.1'}))


if __name__ == '__main__':
    main()
