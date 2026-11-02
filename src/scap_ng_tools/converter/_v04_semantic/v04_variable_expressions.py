"""Decision 29: closed native expression/type validation, never value execution.

The isolated canonical-call candidate is deliberately not imported. Collection
flags, multiplicities and runtime lexical-cast failures are not evaluated here.
"""
from functools import lru_cache
import json
import re
from pathlib import Path

from .v04_comparison_types import TEXT_TYPES, scalar_type, contract
from . import snapshot



@lru_cache(maxsize=1)
def declaration_validator():
    from jsonschema import Draft202012Validator
    from referencing import Registry
    from .v04_object_contract import resources
    directory = snapshot().schema_root
    schema = json.loads((directory / 'variable-expression.schema.json').read_text())
    return Draft202012Validator(schema, registry=Registry().with_resources(resources(str(directory)).items()))


def assessment_variable_expressions(assessment):
    """Validate every declaration, including unused nodes, without mutating ASTs."""
    variables = assessment.get('variables', {})
    if not isinstance(variables, dict):
        raise ValueError('variables must be a mapping')
    validator = declaration_validator()
    for name, declaration in variables.items():
        error = next(validator.iter_errors(declaration), None)
        if error:
            route = '/'.join(map(str, error.path))
            raise ValueError(f'Variable {name}/{route}: {error.message}')
    active, completed = set(), {}

    def compatible(actual, expected, where):
        # Explicit numeric widening matches existing typed comparisons; strings
        # never become numbers merely because a consumer asks for a number.
        if expected not in actual and not (expected == 'float' and 'integer' in actual):
            raise ValueError(f'{where}: declared/derived datatype conflict ({sorted(actual)} vs {expected})')

    def literal(value, expected=None):
        if isinstance(value, dict):
            domain = value['datatype']
            payload = value['value']
            if domain == 'record':
                return {'record'}  # Opaque data, never recursively interpreted as code.
            types = literal(payload, domain)
            compatible(types, domain, 'typed literal')
            return {domain}
        values = value if isinstance(value, list) else [value]
        if not values:
            if expected is None:
                raise ValueError('empty literal array needs its declared datatype')
            return {expected}
        types = {scalar_type(v) for v in values}
        if expected in TEXT_TYPES and types == {'string'}:
            return {expected}
        if expected == 'float' and types <= {'integer', 'float'}:
            return {'float'}
        if len(types) != 1:
            raise ValueError('mixed literal array datatypes')
        return types

    def expression(node, declared=None):
        op, value = next(iter(node.items()))
        if op == 'literal':
            return literal(value, declared)
        if op == 'variable':
            return {variable(value)}
        if op == 'values':
            obj = value['object']
            if isinstance(obj, str):
                obj = assessment.get('shared_objects', {}).get(obj)
            if not isinstance(obj, dict) or not isinstance(obj.get('capability'), str):
                raise ValueError('values requires a resolved Object with explicit capability')
            from .v04_object_contract import object_validator
            error = next(object_validator(obj['capability'], str(snapshot().schema_root)).iter_errors(obj), None)
            if error:
                raise ValueError('invalid values Object: ' + error.message)
            fields, records, _, _ = contract(obj['capability'])
            field = value['field']
            if field not in fields:
                raise ValueError('unknown collected-field projection: ' + field)
            return {'record'} if field in records else set(fields[field])
        if op == 'unique':
            domains = expression(value, declared)
            if 'record' in domains:
                raise ValueError('unique supports scalar values, not record transformations')
            return domains
        if op == 'concat':
            for arg in value:
                compatible(expression(arg), 'string', 'concat argument')
            return {'string'}
        if op in ('regex_capture', 'merge'):
            arg = value['value' if op == 'regex_capture' else 'values']
            argument_types = expression(arg)
            if op == 'merge':
                if 'record' in argument_types:
                    raise ValueError('merge requires scalar values')
            else:
                compatible(argument_types, 'string', op + ' argument')
            if op == 'regex_capture':
                # Existing explicit local-Variable result-type boundary. The
                # captured lexical result may be integer 5; the text input is
                # not parsed as an integer. Runtime invalid/empty lexical values
                # remain errors/empty populations, never fabricated zeroes.
                if declared == 'record':
                    raise ValueError('regex_capture cannot derive a record')
                return {declared or 'string'}
            return {'string'}
        raise ValueError('unsupported native Variable expression: ' + op)

    def variable(name):
        if name in active:
            raise ValueError('cyclic Variable reference: ' + name)
        if name in completed:
            return completed[name]
        if name not in variables:
            raise ValueError('unresolved Variable reference: ' + name)
        active.add(name)
        declaration = variables[name]
        datatype = declaration['datatype']
        derived = expression(declaration['expression'], datatype)
        # Pinned original local_variable tst827 explicitly declares integer but
        # contains literal_component datatype=string '9'. Preserve this existing
        # declaration cast, validate its lexical input, and never rewrite ASTs.
        # Constant arrays and typed literal payloads still obey their own types.
        expr = declaration['expression']
        if (declaration['kind'] == 'local' and set(expr) == {'literal'}
                and derived == {'string'} and datatype in {'integer', 'float'}):
            payload = expr['literal']
            if isinstance(payload, dict): payload = payload['value']
            values = payload if isinstance(payload, list) else [payload]
            pattern = (r'[+-]?[0-9]+' if datatype == 'integer' else
                       r'[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?')
            if values and all(isinstance(v, str) and re.fullmatch(pattern, v) for v in values):
                derived = {datatype}
        compatible(derived, datatype, 'Variable ' + name)
        active.remove(name)
        completed[name] = datatype
        return datatype

    for name in variables:
        variable(name)
    return completed


def variable_expression_errors(document):
    from jsonschema import ValidationError
    assessment = document.get('assessment')
    if not isinstance(assessment, dict):
        return
    try:
        assessment_variable_expressions(assessment)
    except (ValueError, KeyError, TypeError, ValidationError) as error:
        yield ValidationError('Native Variable expression: ' + str(error), validator='native_variable_expression')
