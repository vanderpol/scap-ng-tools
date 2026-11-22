#!/usr/bin/env python3
"""Stage a reproducible offline Tools converter bundle.

This build-time artifact contains one exact SCAP-NG 0.4.1 schema snapshot and
one package-owned production converter. It intentionally does not claim a
frozen Python runtime: the manifest records the runtime/dependency hold until
Issue #86's per-platform executable packaging is qualified.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

from scap_ng_tools.contracts.schema_snapshot_v041 import Pinned041SchemaSnapshot
from scap_ng_tools.converter.direct04 import _version_payload

FORMAT = "scap-ng-tools/offline-bundle/1"
PACKAGE = "scap_ng_tools"


def digest_tree(root: Path, *, suffixes=('.py', '.json')) -> tuple[str, list[dict]]:
    checksum = sha256()
    files = []
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.is_symlink() or path.suffix not in suffixes:
            continue
        relative = path.relative_to(root).as_posix()
        raw = path.read_bytes()
        checksum.update(relative.encode() + b'\0' + raw)
        files.append({'path': relative, 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()})
    return checksum.hexdigest(), files


def schema_files(root: Path) -> list[Path]:
    return sorted((*root.glob('*.json'), *(root / 'capability-mappings').rglob('*.json')))


def copy_regular_tree(source: Path, target: Path, *, suffixes):
    for path in sorted(source.rglob('*')):
        if path.is_symlink():
            raise ValueError(f'symlink is not permitted in bundle input: {path}')
        if path.is_file() and path.suffix in suffixes:
            relative = path.relative_to(source)
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)


def manifest_for(bundle: Path) -> dict:
    manifest_path = bundle / 'manifest.json'
    try:
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f'invalid bundle manifest: {error}') from error
    schema_root = bundle / 'schema'
    app_root = bundle / 'app' / PACKAGE
    if not schema_root.is_dir() or not app_root.is_dir():
        raise ValueError('bundle is missing schema or converter package')
    schema_digest, observed_schema = digest_tree(schema_root)
    app_digest, observed_app = digest_tree(app_root)
    if schema_digest != manifest['schema']['tree_sha256']:
        raise ValueError('bundle schema tree digest mismatch')
    if observed_schema != manifest['schema']['files']:
        raise ValueError('bundle schema file manifest mismatch')
    if app_digest != manifest['converter']['package_tree_sha256']:
        raise ValueError('bundle converter package digest mismatch')
    if observed_app != manifest['converter']['package_files']:
        raise ValueError('bundle converter file manifest mismatch')
    return manifest


def stage(*, schema_root: Path, output: Path, source_root: Path):
    if output.exists() or output.is_symlink():
        raise ValueError(f'output already exists: {output}')
    snapshot = Pinned041SchemaSnapshot(schema_root)
    schema_root = snapshot.schema_root
    source_package = source_root / 'src' / PACKAGE
    if not source_package.is_dir():
        raise ValueError(f'converter package not found: {source_package}')
    parent = output.parent.resolve()
    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=output.name + '.tmp.', dir=parent))
    try:
        copy_regular_tree(schema_root, temporary / 'schema', suffixes={'.json'})
        copy_regular_tree(source_package, temporary / 'app' / PACKAGE,
                          suffixes={'.py', '.json'})
        launcher = temporary / 'bin' / 'scapng-convert-v04'
        launcher.parent.mkdir(parents=True, exist_ok=True)
        launcher.write_text(
            '#!/bin/sh\n'
            'set -eu\n'
            'ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)\n'
            'PYTHON=${PYTHON:-python3}\n'
            'export PYTHONPATH="$ROOT/app${PYTHONPATH:+:$PYTHONPATH}"\n'
            'exec "$PYTHON" -m scap_ng_tools.converter.direct04 '\
            '--schema-root "$ROOT/schema" "$@"\n', encoding='utf-8')
        launcher.chmod(0o755)
        version = _version_payload()
        schema_digest, schema_manifest = digest_tree(temporary / 'schema')
        app_digest, app_manifest = digest_tree(temporary / 'app' / PACKAGE)
        manifest = {
            'format': FORMAT,
            'qualification': 'staged_offline_source_bundle',
            'self_contained_runtime': False,
            'network_required_at_runtime': False,
            'runtime_hold': 'requires Python >=3.11 and declared PyYAML/jsonschema dependencies; frozen per-platform executable is not included',
            'converter': {
                'interface': version['converter_interface'],
                'package_tree_sha256': app_digest,
                'package_files': app_manifest,
                'source_checkout_commit': _git_revision(source_root),
            },
            'schema': {
                'canonical_commit': version['canonical_commit'],
                'schema_version': version['schema_version'],
                'tree_sha256': schema_digest,
                'flat_schema_family_sha256': version['flat_schema_family_sha256'],
                'assessment_execution_family_sha256': version['assessment_execution_family_sha256'],
                'assessment_closure_sha256': version['assessment_closure_sha256'],
                'files': schema_manifest,
            },
            'oval_schema_commit': version['oval_schema_commit'],
            'semantic_pack_sha256': version['semantic_pack_sha256'],
            'entrypoint': 'bin/scapng-convert-v04',
        }
        (temporary / 'manifest.json').write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        os.replace(temporary, output)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _git_revision(root: Path) -> str | None:
    try:
        result = subprocess.run(
            ['git', '-C', str(root), 'rev-parse', 'HEAD'],
            check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--schema-root', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--source-root', type=Path,
                        default=Path(__file__).resolve().parents[1])
    parser.add_argument('--verify', type=Path,
                        help='verify an existing bundle instead of staging one')
    args = parser.parse_args()
    try:
        if args.verify:
            manifest = manifest_for(args.verify)
            print(json.dumps({'status': 'verified', 'format': manifest['format'],
                              'schema_family_sha256': manifest['schema']['flat_schema_family_sha256']},
                             sort_keys=True))
        else:
            if args.schema_root is None or args.output is None:
                parser.error('--schema-root and --output are required when staging')
            stage(schema_root=args.schema_root, output=args.output,
                  source_root=args.source_root)
            print(json.dumps({'status': 'staged', 'manifest': str(args.output / 'manifest.json')},
                             sort_keys=True))
    except (OSError, ValueError, KeyError) as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
