"""Fail-closed 0.4 schema snapshot locator, independent of repository name.

All 0.4 JSON bytes are version-frozen; $id URIs remain versioned even though
the physical files now live under a flat `schema/` directory. Consumers must
pass an explicit local snapshot root. No HTTP fetch or floating branch lookup.
"""

from hashlib import sha256
import json
from pathlib import Path
import re


FROZEN_VERSION = '0.4.0'
FROZEN_DIGEST = '5d3b7f9507318c5ca2e85009fd8bc284d906d357b58cd278219c84f9481536a1'
LOGICAL_PREFIX = 'https://scap-ng.dev/schema/v0.4.0/'
EXPECTED_JSON = 145
EXPECTED_SCHEMAS = 35
EXPECTED_REFS = 681
NAME = re.compile(r'^[a-z][a-z0-9]*(?:[._][a-z0-9]+)*$')


class SnapshotError(ValueError):
    """An externally supplied schema tree does not meet the accepted pin."""


def load_json(path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise SnapshotError(f'{path}: duplicate JSON member {key}')
            value[key] = item
        return value

    def nonfinite(value):
        raise SnapshotError(f'{path}: invalid numeric value {value}')

    return json.loads(path.read_bytes(), object_pairs_hook=unique,
                      parse_constant=nonfinite)


def references(value):
    if isinstance(value, list):
        for item in value:
            yield from references(item)
    elif isinstance(value, dict):
        if '$ref' in value:
            yield value['$ref']
        for item in value.values():
            yield from references(item)


def fingerprint(paths, root):
    """Frozen contract digest: sorted relative path, NUL, exact file bytes."""
    checksum = sha256()
    for path in sorted(paths):
        checksum.update(path.relative_to(root).as_posix().encode('utf-8') + b'\0')
        checksum.update(path.read_bytes())
    return checksum.hexdigest()


class FrozenSchemaSnapshot:
    """Audited local `schema/` at an exact 0.4 snapshot, never a network URI.

    `root` may be the whole canonical checkout or its flat `schema/` directory.
    Reject legacy nested layouts so compatibility is never accidentally proved
    using leftover files in a dirty migration checkout.
    """

    def __init__(self, root):
        raw = Path(root)
        path = raw / 'schema' if (raw / 'schema').is_dir() else raw
        if path.is_symlink() or not path.is_dir():
            raise SnapshotError('expected an existing, non-symlink flat schema directory')
        if (path / 'v0.4.0').exists():
            raise SnapshotError('legacy versioned directory present: use a clean flat schema snapshot')
        if not (path / 'assessment.schema.json').is_file():
            raise SnapshotError('assessment.schema.json missing from flat schema root')
        self.schema_root = path.resolve(strict=True)
        self._validate()

    def _validate(self):
        paths = sorted((*self.schema_root.glob('*.json'),
                        *(self.schema_root / 'capability-mappings').rglob('*.json')))
        if any(path.is_symlink() for path in paths):
            raise SnapshotError('schema snapshot contains symlinked JSON files')
        if len(paths) != EXPECTED_JSON:
            raise SnapshotError(f'expected {EXPECTED_JSON} frozen JSON files; found {len(paths)}')
        actual_digest = fingerprint(paths, self.schema_root)
        if actual_digest != FROZEN_DIGEST:
            raise SnapshotError(f'frozen 0.4 JSON digest mismatch: {actual_digest}')

        roots = sorted(self.schema_root.glob('*.schema.json'))
        if len(roots) != EXPECTED_SCHEMAS:
            raise SnapshotError('wrong number of root JSON Schemas')
        ref_count = 0
        for path in roots:
            document = load_json(path)
            if (document.get('$id') != LOGICAL_PREFIX + path.name or
                    document.get('x-scap-ng-version') != FROZEN_VERSION or
                    document.get('$schema') != 'https://json-schema.org/draft/2020-12/schema'):
                raise SnapshotError(f'{path}: incompatible logical schema identity')
            ref_count += sum(1 for _ in references(document))
        if ref_count != EXPECTED_REFS:
            raise SnapshotError(f'expected {EXPECTED_REFS} root $refs; found {ref_count}')

        scope = load_json(self.schema_root / 'capability-scope.json')
        supported = sorted((self.schema_root / 'capability-mappings' / 'supported').glob('*.json'))
        if len(supported) != scope['supported']['expected_count'] or len(supported) != 100:
            raise SnapshotError('unexpected supported capability count')
        self._supported_paths = {}
        for path in supported:
            item = load_json(path)
            if item.get('capability') != path.stem or item.get('specification_version') != FROZEN_VERSION:
                raise SnapshotError(f'{path}: capability metadata identity mismatch')
            self._supported_paths[path.stem] = path

    def supported_mapping(self, capability):
        if not isinstance(capability, str) or not NAME.fullmatch(capability):
            raise SnapshotError('invalid capability name')
        try:
            path = self._supported_paths[capability]
        except KeyError as exc:
            raise SnapshotError(f'unsupported 0.4 capability: {capability}') from exc
        return load_json(path)

    def supported_mappings(self, capabilities=None):
        names = sorted(self._supported_paths) if capabilities is None else list(capabilities)
        if len(names) != len(set(names)):
            raise SnapshotError('duplicate capability selection')
        return [self.supported_mapping(name) for name in names]

    def manifest(self):
        return {
            'schema_version': FROZEN_VERSION,
            'physical_layout': 'schema/',
            'logical_id_prefix': LOGICAL_PREFIX,
            'schema_json_count': EXPECTED_JSON,
            'root_schema_count': EXPECTED_SCHEMAS,
            'root_ref_count': EXPECTED_REFS,
            'supported_capability_count': len(self._supported_paths),
            'aggregate_sha256': FROZEN_DIGEST,
            'external_snapshot_required': True,
        }
