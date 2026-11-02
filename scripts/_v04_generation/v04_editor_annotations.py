"""Version-local presentation patches; never validation/runtime defaults (#269)."""
from copy import deepcopy
import json
from pathlib import Path

ANNOTATIONS = {'title', 'description', 'examples', 'default', 'x-scap-ng-authoring'}
MAPS = {'properties', 'patternProperties', '$defs', 'definitions', 'dependentSchemas'}
SINGLE = {'items', 'contains', 'additionalProperties', 'unevaluatedProperties',
          'propertyNames', 'not', 'if', 'then', 'else', 'additionalItems'}
ARRAYS = {'oneOf', 'anyOf', 'allOf', 'prefixItems'}


def semantic_schema(schema):
    """Independent keyword-aware erasure: enum/const payloads are opaque data."""
    if not isinstance(schema, dict): return deepcopy(schema)
    out = {}
    for key, value in schema.items():
        if key in ANNOTATIONS: continue
        if key in MAPS:
            value = {name: semantic_schema(child) for name, child in value.items()}
        elif key in SINGLE: value = semantic_schema(value)
        elif key in ARRAYS: value = [semantic_schema(child) for child in value]
        out[key] = deepcopy(value)
    return out


def pointer(document, path):
    node = document
    for part in path.lstrip('/').split('/') if path else []:
        part = part.replace('~1', '/').replace('~0', '~')
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node


def apply_authoring_metadata(schema, root):
    path = Path(root) / 'schema/v0.4.0/editor-default-policy.json'
    if not path.is_file(): return schema  # Isolated source-schema refresh fixtures.
    policy = json.loads(path.read_text())
    if policy['schema_version'] != '0.4.0' or policy['format'] != 'scap-ng/editor-default-policy/1':
        raise ValueError('incompatible authoring metadata policy')
    for patch in policy['patches']:
        if patch['schema_uri'] != schema['$id']: continue
        node = pointer(schema, patch['pointer'])
        for key, value in patch['annotations'].items():
            if key not in ANNOTATIONS: raise ValueError('non-presentation schema patch')
            if key == 'x-scap-ng-authoring':
                node[key] = {**node.get(key, {}), **deepcopy(value)}
            else: node[key] = deepcopy(value)
    return schema
