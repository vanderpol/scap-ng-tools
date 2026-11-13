"""Pure, opt-in migration of the recovered OVAL variable-function forms.

This module does not modify source files or change production converter output.
The caller is responsible for validating the result and preserving provenance.
"""

from copy import deepcopy


class UnsupportedExpression(ValueError):
    pass


def canonical_expression(node, *, allow_existing=False):
    """Return the active 0.4 expression grammar; reject inactive envelopes.

    Native 0.4 uses one-key recursive expressions.  The historical
    ``function`` envelope is intentionally never emitted by this migration.
    """
    if not isinstance(node, dict) or len(node) != 1:
        raise UnsupportedExpression('expression must have exactly one operator')
    op, value = next(iter(node.items()))
    if op in ('literal', 'variable', 'values'):
        return deepcopy(node)
    if op == 'function':
        raise UnsupportedExpression('inactive function envelope is not native 0.4 syntax')
    if op == 'count':
        if not isinstance(value, dict):
            raise UnsupportedExpression('count requires exactly one nested expression')
        return {'count': canonical_expression(value)}
    if op == 'concat':
        if not isinstance(value, list) or len(value) < 2:
            raise UnsupportedExpression('concat requires at least two arguments')
        return {'concat': [canonical_expression(arg) for arg in value]}
    if op == 'regex_capture':
        if not isinstance(value, dict) or set(value) != {'pattern', 'value'} or not isinstance(value['pattern'], str):
            raise UnsupportedExpression('regex_capture requires pattern and value')
        return {'regex_capture': {'pattern': value['pattern'], 'value': canonical_expression(value['value'])}}
    if op == 'merge':
        if not isinstance(value, dict) or set(value) != {'delimiter', 'sort', 'order', 'values'}:
            raise UnsupportedExpression('merge requires exact existing operands and options')
        return {'merge': {'delimiter': value['delimiter'], 'sort': value['sort'], 'order': value['order'], 'values': canonical_expression(value['values'])}}
    if op == 'unique':
        if not isinstance(value, dict):
            raise UnsupportedExpression('unique requires exactly one nested expression')
        return {'unique': canonical_expression(value)}
    raise UnsupportedExpression(f'unrecognized native expression: {op}')


def canonical_assessment(document):
    """Migrate local Variable expressions in a copy; never rewrite other fields."""
    result = deepcopy(document)
    variables = result.get('assessment', {}).get('variables', {})
    if not isinstance(variables, dict):
        raise UnsupportedExpression('assessment.variables must be an object')
    for variable in variables.values():
        if isinstance(variable, dict) and variable.get('kind') == 'local' and 'expression' in variable:
            variable['expression'] = canonical_expression(variable['expression'])
    return result


def legacy_expression(node):
    """Inverse of the currently supported four-function migration subset."""
    if not isinstance(node, dict) or len(node) != 1:
        raise UnsupportedExpression('expression must have exactly one operator')
    op, value = next(iter(node.items()))
    if op in ('literal', 'variable', 'values'):
        return deepcopy(node)
    if op != 'function' or not isinstance(value, dict) or set(value) != {'name', 'arguments', 'options'}:
        raise UnsupportedExpression('not a canonical function')
    name, args, options = value['name'], value['arguments'], value['options']
    if not isinstance(args, list) or not isinstance(options, dict):
        raise UnsupportedExpression('invalid arguments/options')
    if name == 'count' and len(args) >= 1 and not options:
        values = [legacy_expression(arg) for arg in args]
        return {'count': values if len(values) > 1 else values[0]}
    if name == 'concat' and len(args) >= 2 and not options:
        return {'concat': [legacy_expression(a) for a in args]}
    if name == 'regex_capture' and len(args) == 1 and set(options) == {'pattern'}:
        return {'regex_capture': {'pattern': options['pattern'], 'value': legacy_expression(args[0])}}
    if name == 'unique' and len(args) == 1 and not options:
        return {'unique': legacy_expression(args[0])}
    if name == 'merge' and len(args) == 1 and set(options) == {'delimiter', 'sort', 'order'}:
        return {'merge': {**deepcopy(options), 'values': legacy_expression(args[0])}}
    raise UnsupportedExpression(f'canonical call outside legacy migration subset: {name}')
