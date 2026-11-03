"""Inventory the approved native function AST subset; never evaluate values.

Literal data and Object selectors are opaque. Program format changes only when
an active function occurs in a Variable expression. Refs scap-ng#10/tools#14.
"""
from hashlib import sha256
import json

FUNCTION_PROGRAM_FORMAT = 'scap-ng-0.4.0-native-assessment-program/0.3'
FUNCTION_CONTRACT_VERSION = 1


def function_inventory(assessment):
    rows = []

    def walk(node, path):
        op, value = next(iter(node.items()))
        if op == 'function':
            rows.append({'name': value['name'], 'source_path': path,
                'source_sha256': sha256(json.dumps(node, sort_keys=True,
                    ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()).hexdigest()})
            for i, arg in enumerate(value['arguments']):
                walk(arg, path + '/function/arguments/' + str(i))
        elif op == 'concat':
            for i, arg in enumerate(value): walk(arg, path + '/concat/' + str(i))
        elif op == 'regex_capture': walk(value['value'], path + '/regex_capture/value')
        elif op == 'merge': walk(value['values'], path + '/merge/values')
        elif op == 'unique': walk(value, path + '/unique')
        # literal, variable and values do not contain expression children.

    for name, decl in assessment.get('variables', {}).items():
        token = name.replace('~', '~0').replace('/', '~1')
        walk(decl['expression'], '/variables/' + token + '/expression')
    return sorted(rows, key=lambda row: row['source_path'])
