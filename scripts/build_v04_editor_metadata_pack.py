#!/usr/bin/env python3
"""Export the reviewed owner-amended 0.4 editor schema/mapping/vocabulary pack.

The accepted 2026-11-02 pre-release Item grouping amendment deliberately
changes the schema/vocabulary resource digest. All other source-generated
capability resources are still checked by this exact audited identity.
This builds an unsigned local artifact. Distribution and editor consumption
are separate owner-controlled steps.
"""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from scap_ng_tools.contracts import FrozenSchemaSnapshot

from generate_v04_semantic_pack import GENERATOR, OVAL_COMMIT, git_head


# Original research exporter at d12a644f4607cdc9c9ada50e3a96d4fd0060c6d9;
# 235 deterministic resource descriptors, 100 capability identities, one URI.
# Source commit is purposely excluded from this digest.
HISTORICAL_RESOURCES_SHA256 = 'faa1c81c01c34a212e33827e3628f9c355255c1030fa8aa8936cb9d28522c564'
PRE_DISCOVERY_RESOURCES_SHA256 = '0297c8367f828123bcec8afe39d8a85712a51d938e3c918081eb9be41d75b562'
PRE_FUNCTION_RESOURCES_SHA256 = 'a88006cea5973d88773b6a3e1ac31bf4d0fd386ead77b3c2cfd18c1b116dfeda'
REVIEWED_RESOURCES_SHA256 = 'fa1398c16a6fcc91b1acf9a37bd70c56d4d6de7ec1233ce407b438a4b475ea6a'
COMMIT = re.compile(r'^[a-f0-9]{40}$')


def generate_editor_capabilities(mappings, root):
    """Keep original generator-only v04_* imports out of the converter runtime."""
    generator_path = str(GENERATOR)
    sys.path.insert(0, generator_path)
    try:
        from generate_capability_schema_v04 import generate  # noqa: E402
        return {mapping['capability']: generate(mapping, root, authoring_metadata=True)
                for mapping in mappings}
    finally:
        # The portable converter explicitly refuses same-named foreign v04_*
        # modules; the pack exporter must not pollute another caller's process.
        sys.path.remove(generator_path)
        for name, module in tuple(sys.modules.items()):
            origin = getattr(module, '__file__', None)
            if origin and Path(origin).resolve().parent == GENERATOR:
                del sys.modules[name]


def build(schema_root, oval_root, source_commit, output):
    snapshot = FrozenSchemaSnapshot(schema_root)
    source_commit = str(source_commit)
    schema_repo = snapshot.schema_root.parent
    if not COMMIT.fullmatch(source_commit) or git_head(schema_repo) != source_commit:
        raise ValueError('sourceCommit must match the exact checked-out flat schema commit')
    dirty = subprocess.check_output(
        ['git', '-C', str(schema_repo), 'status', '--porcelain', '--', 'schema'],
        text=True).strip()
    if dirty:
        raise ValueError('commit changes in the schema tree before exporting')

    oval_root = Path(oval_root).resolve(strict=True)
    if git_head(oval_root) != OVAL_COMMIT:
        raise ValueError('official OVAL source is not the audited v5.12.3 commit')
    xsd_root = oval_root / 'oval-schemas'
    if len(list(xsd_root.glob('*.xsd'))) != 54:
        raise ValueError('incomplete OVAL v5.12.3 schema set')
    output = Path(output).absolute()
    if output.exists():
        raise ValueError('refusing to overwrite existing editor metadata pack')
    if not output.parent.is_dir():
        raise ValueError('output parent directory must exist')

    with tempfile.TemporaryDirectory(prefix='scapng-v04-editor-input-') as original:
        # Adapter exists only during derivation; no historical schema path or
        # OVAL XSD is shipped in the resulting editor metadata pack.
        root = Path(original)
        (root / 'schema').mkdir()
        (root / 'schema' / 'v0.4.0').symlink_to(
            snapshot.schema_root, target_is_directory=True)
        source = root / 'third_party' / 'scap-1.4-schemas'
        source.mkdir(parents=True)
        (source / 'oval_5.12.3').symlink_to(xsd_root, target_is_directory=True)
        mappings = snapshot.supported_mappings()
        generated = generate_editor_capabilities(mappings, root)

        with tempfile.TemporaryDirectory(
                prefix='.scapng-v04-editor-pack-', dir=output.parent) as destination:
            stage = Path(destination) / 'pack'
            stage.mkdir()
            resources, capabilities = [], {}

            def add(document, relative, kind, uri=None):
                raw = (json.dumps(document, indent=2, sort_keys=True) + '\n').encode()
                target = stage / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                resources.append({
                    'uri': uri or document['$id'],
                    'path': relative,
                    'kind': kind,
                    'bytes': len(raw),
                    'sha256': sha256(raw).hexdigest(),
                })

            for file in sorted(snapshot.schema_root.glob('*.schema.json')):
                add(json.loads(file.read_bytes()), 'schemas/' + file.name, 'schema')
            # Sort complete filenames, not just capability names: e.g.
            # solaris.package.ips.json sorts before solaris.package.json.
            # Resource-array order is a versioned part of the manifest hash.
            for file in sorted((snapshot.schema_root /
                                'capability-mappings/supported').glob('*.json')):
                mapping = json.loads(file.read_bytes())
                capability = mapping['capability']
                mapping_uri = 'scap-ng:mapping:0.4.0:' + capability
                add(generated[capability], 'capabilities/' + capability + '.json', 'schema')
                add(mapping, 'mappings/' + capability + '.json', 'mapping', mapping_uri)
                capabilities[capability] = {
                    'schema_uri': generated[capability]['$id'], 'mapping_uri': mapping_uri}
            vocabulary_uri = 'scap-ng:vocabulary:0.4.0:en'
            add(json.loads((snapshot.schema_root /
                            'authoring-vocabulary.en.json').read_bytes()),
                'vocabulary/en.json', 'vocabulary', vocabulary_uri)

            resource_identity = json.dumps({
                'resources': resources, 'capabilities': capabilities,
                'vocabulary_uri': vocabulary_uri,
            }, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
            if (len(resources) != 235 or len(capabilities) != 100 or
                    sha256(resource_identity).hexdigest() != REVIEWED_RESOURCES_SHA256):
                raise ValueError('generated editor metadata resource drift detected: ' +
                                 sha256(resource_identity).hexdigest())
            manifest = {
                'format': 'scap-ng/offline-editor-pack/1',
                'schema_version': '0.4.0',
                'authoring_metadata_version': 1,
                'source_commit': source_commit,
                'resources': resources,
                'capabilities': capabilities,
                'vocabulary_uri': vocabulary_uri,
            }
            manifest_raw = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
            (stage / 'manifest.json').write_bytes(manifest_raw)
            profile = {
                'schemaVersion': '0.4.0',
                'sourceCommit': source_commit,
                'manifestSha256': sha256(manifest_raw).hexdigest(),
            }
            (stage / 'profile.json').write_text(json.dumps(profile, indent=2) + '\n')
            if output.exists():
                raise ValueError('output created concurrently; refusing to overwrite')
            stage.rename(output)
            return profile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--schema-root', type=Path, required=True)
    parser.add_argument('--oval-root', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.schema_root, args.oval_root,
                           args.source_commit, args.output), sort_keys=True))


if __name__ == '__main__':
    main()
