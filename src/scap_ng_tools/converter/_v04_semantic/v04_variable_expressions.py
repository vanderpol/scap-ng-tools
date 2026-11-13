"""Closed native expression/type validation, never value execution.

Function calls are checked as typed collection transformations.  This module
does not execute values: cardinality, Cartesian products, ordering and status
propagation are runtime contracts covered by the independent OVAL oracle.
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
    # The historical 0.4 snapshots and the approved inference candidate are
    # distinct pinned authoring contracts. Do not silently reinterpret a
    # historical Variable's declared result cast against new semantics.
    declaration_schema = getattr(validator, 'schema', {}).get('$defs', {}).get('declaration', {})
    declared_type_required = 'datatype' in declaration_schema.get('required', [])
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

    def text_operand(actual, where):
        # OVAL FunctionGroup permits an attempted cast to string for textual
        # functions.  Preserve that explicit lexical boundary: records and
        # unknown/empty domains are not silently flattened, while scalar
        # integer/float/boolean values are stringified by the runtime contract.
        scalar_domains = TEXT_TYPES | {'integer', 'float', 'boolean'}
        if not actual or 'record' in actual or not actual <= scalar_domains:
            raise ValueError(f'{where} requires a scalar text operand')
        return actual

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
            # Empty collections carry no scalar datatype.  Consumers such as
            # count may still operate on them; typed string consumers pass an
            # expected domain and therefore remain explicit.
            return set() if expected is None else {expected}
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
        if op == 'function':
            if (not isinstance(value, dict) or set(value) != {'name', 'arguments', 'options'}):
                raise ValueError('function expression requires name, arguments, and options')
            name, arguments, options = value['name'], value['arguments'], value['options']
            if not isinstance(arguments, list) or not isinstance(options, dict):
                raise ValueError('function expression has invalid arguments/options')
            if name == 'arithmetic':
                if len(arguments) < 2 or set(options) != {'arithmetic_operation'}:
                    raise ValueError('arithmetic requires two arguments and explicit operation')
                if options['arithmetic_operation'] not in ('add', 'multiply'):
                    raise ValueError('unsupported arithmetic operation')
                domains = [expression(argument) for argument in arguments]
                if any(not domain or not domain <= {'integer', 'float'} for domain in domains):
                    raise ValueError('arithmetic requires numeric operands')
                return {'float'} if any('float' in domain for domain in domains) else {'integer'}
            if name in ('split', 'substring'):
                if len(arguments) != 1:
                    raise ValueError(name + ' requires one argument')
                if name == 'split':
                    if set(options) != {'delimiter'} or not isinstance(options['delimiter'], str):
                        raise ValueError('split requires a literal string delimiter')
                else:
                    required = {'substring_start', 'substring_length'}
                    if set(options) != required:
                        raise ValueError('substring requires explicit signed integer options')
                    if any(isinstance(options[key], bool) or not isinstance(options[key], int)
                           or not -2147483648 <= options[key] <= 2147483647 for key in required):
                        raise ValueError('substring options must be signed 32-bit integers')
                domain = text_operand(expression(arguments[0]), name)
                return {'string'}
            if name == 'count':
                if len(arguments) < 1 or options:
                    raise ValueError('count requires one or more arguments and no options')
                # Count is the one function in this group whose input domain
                # is intentionally unconstrained: OVAL counts flattened
                # values, including records and empty populations.
                for argument in arguments:
                    expression(argument)
                return {'integer'}
            if name == 'concat':
                if len(arguments) < 2 or options:
                    raise ValueError('concat requires at least two arguments and no options')
                for argument in arguments:
                    text_operand(expression(argument), 'concat')
                return {'string'}
            if name == 'regex_capture':
                if len(arguments) != 1 or set(options) != {'pattern'} or not isinstance(options['pattern'], str):
                    raise ValueError('regex_capture requires one string argument and a pattern')
                text_operand(expression(arguments[0]), 'regex_capture')
                return {'string'}
            if name == 'unique':
                if len(arguments) < 1 or options:
                    raise ValueError('unique requires one or more arguments and no options')
                for argument in arguments:
                    text_operand(expression(argument), 'unique')
                return {'string'}
            if name == 'merge':
                required = {'delimiter', 'sort', 'order'}
                if len(arguments) < 1 or set(options) != required:
                    raise ValueError('merge requires one or more arguments and explicit options')
                if (not isinstance(options['delimiter'], str) or
                        options['sort'] not in ('document', 'lexical', 'numeric', 'natural') or
                        options['order'] not in ('ascending', 'descending')):
                    raise ValueError('merge has invalid explicit options')
                for argument in arguments:
                    domain = expression(argument)
                    # OVAL merge stringifies simple values, but a record is
                    # not a simple value and cannot be silently flattened.
                    if not domain or 'record' in domain:
                        raise ValueError('merge requires scalar values')
                return {'string'}
            raise ValueError('unsupported native Variable function: ' + str(name))
        if op == 'count':
            expression(value)  # Any resolved typed collection, including empty.
            return {'integer'}
        if op in ('split', 'substring', 'begin', 'end'):
            payload = value
            if not isinstance(payload, dict) or 'value' not in payload:
                raise ValueError(op + ' requires a value expression')
            domain = expression(payload['value'])
            if domain != {'string'}:
                raise ValueError(op + ' requires string input; no implicit cast')
            return {'string'}
        if op == 'arithmetic':
            domains = [expression(arg) for arg in value['values']]
            if any(not domain or not domain <= {'integer', 'float'} for domain in domains):
                raise ValueError('arithmetic requires typed numeric operands')
            return {'float'} if any('float' in domain for domain in domains) else {'integer'}
        if op == 'unique':
            if declared_type_required:
                # Preserve the historical frozen schema's exact string-domain
                # behavior; only the inference candidate inherits input type.
                text_operand(expression(value), 'unique')
                return {'string'}
            # Unique preserves the type of its input (and first occurrence
            # order) under the new expression-derived type contract.
            components = value if isinstance(value, list) else [value]
            domains = [expression(component) for component in components]
            result = set().union(*domains) if domains else set()
            if len(result) > 1 or 'record' in result:
                raise ValueError('unique requires one scalar datatype')
            return result
        if op == 'concat':
            for arg in value:
                text_operand(expression(arg), 'concat')
            return {'string'}
        if op in ('regex_capture', 'merge'):
            arg = value['value' if op == 'regex_capture' else 'values']
            argument_types = expression(arg)
            if op == 'merge':
                if not argument_types or 'record' in argument_types:
                    raise ValueError('merge requires scalar values')
                return {'string'}
            text_operand(argument_types, 'regex_capture')
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
        if declared_type_required:
            datatype = declaration['datatype']
            derived = expression(declaration['expression'], datatype)
            # Preserve the old snapshot's precisely bounded lexical-literal
            # adaptation; it is not admitted in the inference candidate.
            expr = declaration['expression']
            if (declaration['kind'] == 'local' and set(expr) == {'literal'}
                    and derived == {'string'} and datatype in {'integer', 'float'}):
                payload = expr['literal']
                if isinstance(payload, dict):
                    payload = payload['value']
                values = payload if isinstance(payload, list) else [payload]
                pattern = (r'[+-]?[0-9]+' if datatype == 'integer' else
                           r'[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?')
                if values and all(isinstance(v, str) and re.fullmatch(pattern, v) for v in values):
                    derived = {datatype}
            compatible(derived, datatype, 'Variable ' + name)
        else:
            # Native inference NEVER converts a source lexical string into
            # numeric output merely because a consumer expects a number.
            derived = expression(declaration['expression'])
            if len(derived) != 1:
                raise ValueError('Variable ' + name +
                                 ': ambiguous/empty result datatype; use an explicitly typed literal or uniquely typed collected field')
            datatype = next(iter(derived))
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
