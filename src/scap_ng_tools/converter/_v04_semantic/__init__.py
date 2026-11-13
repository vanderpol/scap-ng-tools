"""The sole offline SCAP-NG 0.4.1 semantic contract pack.

The pack is generated from the exact canonical 0.4.1 schema snapshot and the
pinned OVAL XSD source. Runtime never falls back to an older schema or pack.
It proves structural/native authoring contracts only; it does not prove source
scanner equivalence.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import lru_cache
from hashlib import sha256
import json
from pathlib import Path

from scap_ng_tools.contracts.schema_snapshot_v041 import Pinned041SchemaSnapshot

PACK_HASH = 'b5f654229c40dfeb0d2f0b486c2b50c78bf569617c8ec309fa0637f4368195ba'
SCHEMA_HASH = '578315d1e00bd39449ed597ed3d39555384276bd36198a54ca0b1e3c17e72829'
RESEARCH_COMMIT = 'd12a644f4607cdc9c9ada50e3a96d4fd0060c6d9'
OVAL_COMMIT = '2f140ee5c5dd1ed9606fcd5afc301f6baeb48706'
GENERATOR_HELPER_SHA256 = {
    'generate_capability_schema_v04.py': 'df7545ed9fc7de40363aa64f286a82f2cd5b4d8175070833dbf9590a5c54b986',
    'v04_capability_native.py': '14d8a88474b1238352a6d35e7da247de41fbc65a26b8c5764c9406553807e09b',
    'v04_capability_source.py': 'b2e4a1cb053acc574b7677ef7d94a38905ce9acdd8a418be613840b330ca44e5',
    'v04_editor_annotations.py': 'ed47166e8cc82f9c319c5bc2829c6ffa0c8671682a9b3777e1c541cc37086072',
}
PACK_FORMAT = 'scap-ng-portable-0.4.1-semantic-pack/1'
_selected = ContextVar('scap_ng_v041_semantic_schema', default=None)


@contextmanager
def selected_schema(snapshot):
    if not isinstance(snapshot, Pinned041SchemaSnapshot):
        raise ValueError('semantic validation requires the approved 0.4.1 schema snapshot')
    token = _selected.set(snapshot)
    try:
        yield
    finally:
        _selected.reset(token)


def snapshot():
    current = _selected.get()
    if current is None:
        raise ValueError('0.4.1 semantic validation requires an explicit schema context')
    return current


@lru_cache(maxsize=1)
def contracts():
    path = Path(__file__).with_name('contracts-0.4.1.json')
    raw = path.read_bytes()
    if sha256(raw).hexdigest() != PACK_HASH:
        raise ValueError('0.4.1 semantic pack checksum mismatch')
    value = json.loads(raw)
    if (value.get('format') != PACK_FORMAT or
            value.get('schema_version') != '0.4.1' or
            value.get('oval_commit') != OVAL_COMMIT or
            value.get('generator_helper_sha256') != GENERATOR_HELPER_SHA256 or
            value.get('frozen_schema_digest') != SCHEMA_HASH or
            value.get('research_generator_commit') != RESEARCH_COMMIT or
            len(value.get('capabilities', {})) != 52 or
            not value.get('behavior_attributes')):
        raise ValueError('0.4.1 semantic pack identity mismatch')
    return value


def capability_contract(capability):
    if not isinstance(capability, str):
        raise ValueError('unknown native 0.4.1 capability ' + repr(capability))
    current = snapshot()
    try:
        mapping = current.supported_mapping(capability)
        contract = contracts()['capabilities'][capability]
    except (KeyError, ValueError) as error:
        raise ValueError('unknown native 0.4.1 capability ' + repr(capability)) from error
    return mapping, contract


def behavior_declarations(schema_path, object_name):
    key = schema_path + '::' + object_name
    try:
        return contracts()['behavior_attributes'][key]
    except KeyError as error:
        raise ValueError('unrecognized 0.4.1 behavior contract: ' + key) from error


@lru_cache(maxsize=2)
def schema_resources(schema_dir):
    from referencing import Resource
    result = {}
    for path in sorted(Path(schema_dir).glob('*.schema.json')):
        document = json.loads(path.read_bytes())
        resource = Resource.from_contents(document)
        result[document['$id']] = resource
    return result
