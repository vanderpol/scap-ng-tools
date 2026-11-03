"""Bind self-describing float predicates to the reviewed binary32 contract.

Only grammar-owned comparison sites are traversed; literal data stays opaque.
No cast/comparison execution occurs during compilation. Refs #218/#255.
"""
from hashlib import sha256
import json

from .binary32 import CONTRACT_ID, CONTRACT_SHA256, OPERATIONS, expected_bits

FLOAT_PROGRAM_FORMAT = 'scap-ng-0.4.0-native-assessment-program/0.4'


def float_inventory(assessment):
    from ._v04_semantic.v04_object_contract import object_sites
    rows = {}

    def token(value):
        return str(value).replace('~', '~0').replace('/', '~1')

    def predicate(node, path):
        for operation in OPERATIONS:
            name = 'float_' + operation
            if name not in node:
                continue
            values = node[name] if isinstance(node[name], list) else [node[name]]
            for value in values:
                if not isinstance(value, dict):
                    expected_bits(value)
            rows[path] = {'operator': name, 'source_path': path,
                'source_sha256': sha256(json.dumps(node, sort_keys=True, ensure_ascii=False,
                    separators=(',', ':'), allow_nan=False).encode()).hexdigest()}
        if isinstance(node.get('record'), dict):
            condition(node['record'], path + '/record')

    def condition(node, path, flat=False):
        for operation in ('and', 'or', 'one', 'xor'):
            for index, child in enumerate(node.get(operation, [])):
                condition(child, path + '/' + operation + '/' + str(index))
        fields = node.get('fields', {})
        if flat and not set(node) & {'fields', 'and', 'or', 'one', 'xor'}:
            fields = {key: value for key, value in node.items() if key != 'field_requirement'}
        for field, value in fields.items():
            predicate(value, path + ('/fields/' if fields is node.get('fields') else '/') + token(field))

    for name, test in assessment.get('tests', {}).items():
        condition(test.get('require', {}), '/tests/' + token(name) + '/require')
    for site in object_sites(assessment):
        from ._v04_semantic.v04_comparison_types import contract
        _, _, selectors, native = contract(site.capability)
        domains = {**native.get('field_datatypes', {}), **selectors}
        parts = site.path[1:] if site.path[0] == 'assessment' else site.path
        path = '/' + '/'.join(token(part) for part in parts)
        for name, value in site.node.items():
            if isinstance(value, dict) and 'float' in domains.get(name, []):
                predicate(value, path + '/' + token(name))
        # Set filters belong to the containing Object, not its literal payloads.
        def filters(node, route):
            for index, operand in enumerate(node.get('operands', [])):
                p = route + '/operands/' + str(index)
                for j, flt in enumerate(operand.get('filters', [])):
                    for action in ('include', 'exclude'):
                        if action in flt:
                            condition(flt[action], p + '/filters/' + str(j) + '/' + action, flat=True)
                if isinstance(operand.get('set'), dict):
                    filters(operand['set'], p + '/set')
        if isinstance(site.node.get('set'), dict):
            filters(site.node['set'], path + '/set')
    return sorted(rows.values(), key=lambda row: row['source_path'])


def float_contract():
    return {'id': CONTRACT_ID, 'sha256': CONTRACT_SHA256}


def comparison_errors(document):
    from jsonschema import ValidationError
    assessment = document.get('assessment')
    if (not isinstance(assessment, dict) or assessment.get('mode') != 'automated'
            or (assessment.get('specification') or {}).get('version') != '0.4.0'):
        return
    try:
        float_inventory(assessment)
    except (ValueError, KeyError, TypeError) as error:
        yield ValidationError('Binary32 comparison contract: ' + str(error), validator='binary32_comparison_contract')
