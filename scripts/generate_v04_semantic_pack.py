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
import xml.etree.ElementTree as ET

from scap_ng_tools.contracts.schema_snapshot_v041 import (
    ASSESSMENT_CLOSURE_SHA256, ASSESSMENT_EXECUTION_FAMILY_SHA256,
    CANONICAL_COMMIT, fingerprint,
)

from scap_ng_tools.contracts.schema_snapshot_v041 import Pinned041SchemaSnapshot
from scap_ng_tools.converter.direct04 import load_runtime


OVAL_COMMIT = '2f140ee5c5dd1ed9606fcd5afc301f6baeb48706'
RESEARCH_GENERATOR_COMMIT = 'd12a644f4607cdc9c9ada50e3a96d4fd0060c6d9'
GENERATOR = Path(__file__).resolve().parent / '_v04_generation'


def git_head(path):
    return subprocess.check_output(
        ['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()


def original_behavior_attributes(path, object_name):
    """Derive behavior declarations from official XSD, never the old pack."""
    xs = '{http://www.w3.org/2001/XMLSchema}'
    schema = ET.parse(path).getroot()
    obj = schema.find(xs + 'element[@name="' + object_name + '"]')
    declarations = [] if obj is None else obj.findall('.//' + xs + 'element[@name="behaviors"]')
    if len(declarations) != 1:
        raise ValueError('one original behavior declaration required')
    name = declarations[0].get('type', '').split(':')[-1]
    declaration = schema.find(xs + 'complexType[@name="' + name + '"]')
    if declaration is None:
        raise ValueError('original behavior type unavailable')

    def attributes_for(node, active):
        name = node.get('name')
        if name in active:
            raise ValueError('cyclic original behavior inheritance')
        result = {}
        extension = node.find(xs + 'complexContent/' + xs + 'extension')
        if extension is not None:
            base = schema.find(xs + 'complexType[@name="' + extension.get('base').split(':')[-1] + '"]')
            if base is None:
                raise ValueError('unavailable original behavior base')
            result.update(attributes_for(base, active | {name}))
        result.update({a.get('name'): dict(a.attrib) for a in node.findall('.//' + xs + 'attribute')})
        return result

    return attributes_for(declaration, set())


def build(schema_root, oval_root):
    snapshot = Pinned041SchemaSnapshot(schema_root)
    if git_head(snapshot.schema_root.parent) != CANONICAL_COMMIT:
        raise ValueError('canonical source is not the exact reviewed main commit')
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
                behaviors[key] = original_behavior_attributes(
                    root / source['definitions_schema'], source['object'])

    body = {
        'format': 'scap-ng-portable-0.4.1-semantic-pack/1',
        'frozen_schema_digest': snapshot.manifest()['flat_json_aggregate_sha256'],
        # Historical derivation provenance, not a runtime or CI checkout.
        'schema_version': '0.4.1',
        'canonical_commit': CANONICAL_COMMIT,
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
    parser.add_argument('--pin-output', type=Path, help='write exact canonical and regenerated semantic-pack checksums')
    parser.add_argument('--ri-root', type=Path, help='verify the Assessment execution handshake against this exact RI checkout')
    args = parser.parse_args()
    if args.pin_output and not args.ri_root:
        parser.error('--pin-output requires --ri-root for the checked execution handshake')
    raw = build(args.schema_root, args.oval_root)
    args.output.write_text(raw, encoding='utf-8')
    if args.pin_output:
        snapshot = Pinned041SchemaSnapshot(args.schema_root)
        root = snapshot.schema_root
        paths = sorted([*root.glob('*.json'), *(root / 'capability-mappings').rglob('*.json')])
        pin = {'schema_version': '0.4.1', 'single_version': True,
               'canonical_repository': 'vanderpol/scap-ng', 'canonical_sha': CANONICAL_COMMIT,
               'schema_family_sha256': fingerprint(paths, root),
               'semantic_pack_sha256': sha256(raw.encode('utf-8')).hexdigest(),
               'oval_commit': OVAL_COMMIT,
               'files': {p.relative_to(root).as_posix(): {'sha256': sha256(p.read_bytes()).hexdigest(),
                                                       'bytes': p.stat().st_size} for p in paths}}
        ri_pin_path = args.ri_root / 'internal/nativeschema/pin.json'
        ri_pin = json.loads(ri_pin_path.read_bytes())
        closure = snapshot.assessment_closure()
        expected = {name: {'sha256': sha256(raw).hexdigest(), 'bytes': len(raw)}
                    for name, raw in sorted(closure.items())}
        if (ri_pin['family_sha256'] != ASSESSMENT_EXECUTION_FAMILY_SHA256 or
                ri_pin['files'] != expected):
            raise ValueError('RI Assessment execution pin differs from canonical closure')
        pin['assessment_execution'] = {
            'family_sha256': ASSESSMENT_EXECUTION_FAMILY_SHA256,
            'closure_sha256': ASSESSMENT_CLOSURE_SHA256,
            'ri_commit': git_head(args.ri_root),
            'ri_pin_sha256': sha256(ri_pin_path.read_bytes()).hexdigest(),
            'files': expected,
        }
        args.pin_output.write_text(json.dumps(pin, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'capabilities': len(json.loads(raw)['capabilities']), 'bytes': len(raw.encode('utf-8')),
                      'source': 'official OVAL v5.12.3 + canonical flat 0.4.1'}))


if __name__ == '__main__':
    main()
