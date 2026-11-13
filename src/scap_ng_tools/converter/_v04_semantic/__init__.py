"""Isolated, offline 0.4 semantic gate over a frozen flat schema snapshot.

The contract pack is generated from the pinned 0.4 metadata and OVAL XSDs at
build time. Runtime must never need the research repo or the source XSD files.
"""

from contextlib import contextmanager
from contextvars import ContextVar
from functools import lru_cache
from hashlib import sha256
import json
from pathlib import Path

from scap_ng_tools.contracts import FrozenSchemaSnapshot


PACK_HASH = '4b26739f858b280eb0a7b881fd7b3d517904fbeeb038fc80c9d33448ba2c35bf'
SCHEMA_HASH = '910beeebfb90a63c773615907289a0e4b93095ee41cd1ad41b33652363900c74'
RESEARCH_COMMIT = 'd12a644f4607cdc9c9ada50e3a96d4fd0060c6d9'
_selected = ContextVar('scap_ng_v04_semantic_schema', default=None)


@contextmanager
def selected_schema(snapshot):
    if not isinstance(snapshot, FrozenSchemaSnapshot):
        raise ValueError('semantic validation requires an approved frozen 0.4 snapshot')
    token = _selected.set(snapshot)
    try:
        yield
    finally:
        _selected.reset(token)


def snapshot():
    current = _selected.get()
    if current is None:
        raise ValueError('0.4 semantic validation requires an explicit schema context')
    return current


@lru_cache(maxsize=1)
def contracts():
    path = Path(__file__).with_name('contracts-0.4.0.json')
    raw = path.read_bytes()
    if sha256(raw).hexdigest() != PACK_HASH:
        raise ValueError('frozen 0.4 semantic pack checksum mismatch')
    value = json.loads(raw)
    if (value.get('format') != 'scap-ng-portable-0.4-semantic-pack/1' or
            value.get('frozen_schema_digest') != SCHEMA_HASH or
            value.get('research_generator_commit') != RESEARCH_COMMIT or
            len(value.get('capabilities', {})) != 52):
        raise ValueError('frozen 0.4 semantic pack identity mismatch')
    return value


def capability_contract(capability):
    if not isinstance(capability, str):
        raise ValueError('unknown native 0.4 capability ' + repr(capability))
    current = snapshot()
    try:
        mapping = current.supported_mapping(capability)
        contract = contracts()['capabilities'][capability]
    except (KeyError, ValueError) as error:
        raise ValueError('unknown native 0.4 capability ' + repr(capability)) from error
    return mapping, contract


def behavior_declarations(schema_path, object_name):
    key = schema_path + '::' + object_name
    try:
        return contracts()['behavior_attributes'][key]
    except KeyError as error:
        raise ValueError('unrecognized frozen 0.4 behavior contract: ' + key) from error


@lru_cache(maxsize=2)
def schema_resources(schema_dir):
    from referencing import Resource
    result = {}
    for path in sorted(Path(schema_dir).glob('*.schema.json')):
        document = json.loads(path.read_bytes())
        resource = Resource.from_contents(document)
        result[document['$id']] = resource
    return result
