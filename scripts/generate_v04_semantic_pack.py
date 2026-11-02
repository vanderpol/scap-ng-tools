#!/usr/bin/env python3
"""Regenerate a frozen 0.4-only validation pack from the accepted OVAL XSDs.

This is a BUILD-TIME audit tool. The installable converter reads the generated
pack and the externally pinned flat JSON Schema; it never reads old XSD files,
imports the old repo, or guesses at a capability datatype.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

from scap_ng_tools.contracts import FrozenSchemaSnapshot
from scap_ng_tools.converter.direct04 import load_runtime


RESEARCH_COMMIT = 'd12a644f4607cdc9c9ada50e3a96d4fd0060c6d9'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--research-root', type=Path, required=True)
    parser.add_argument('--schema-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.research_root.resolve(strict=True)
    commit = subprocess.check_output(
        ['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    if commit != RESEARCH_COMMIT:
        parser.error(f'research source must be at {RESEARCH_COMMIT}; got {commit}')
    snapshot = FrozenSchemaSnapshot(args.schema_root)
    runtime = load_runtime()
    # The old generator is used solely here and cannot leak into the package.
    sys.path.insert(0, str(root / 'tools'))
    from generate_capability_schema_v04 import (  # noqa: E402
        generate, _generated_state_fields, _selector_fields,
    )
    spec = importlib.util.spec_from_file_location(
        'pinned_research_v04_behavior_extractor',
        root / 'tools/v04_direct_scalar_behaviors.py')
    original = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(original)

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
        if original.behavior_routes(mapping):
            behaviors[source['definitions_schema'] + '::' + source['object']] = (
                original.original_attributes(source['definitions_schema'], source['object']))
    body = {'format': 'scap-ng-portable-0.4-semantic-pack/1',
            'frozen_schema_digest': snapshot.manifest()['aggregate_sha256'],
            'research_generator_commit': RESEARCH_COMMIT,
            'capabilities': capabilities, 'behavior_attributes': behaviors}
    args.output.write_text(json.dumps(body, sort_keys=True,
                                      separators=(',', ':'), ensure_ascii=False) + '\n',
                           encoding='utf-8')
    print(json.dumps({'capabilities': len(capabilities),
                      'output_bytes': args.output.stat().st_size}))


if __name__ == '__main__':
    main()
