"""Pure, opt-in migration of the four currently emitted OVAL function forms.

This module does not modify source files or change production converter output.
The caller is responsible for validating the result and preserving provenance.
"""

from copy import deepcopy


class UnsupportedExpression(ValueError):
    pass


def canonical_expression(node):
    """Return a new canonical function expression; reject unknown grammar."""
    if not isinstance(node, dict) or len(node) != 1:
        raise UnsupportedExpression('expression must have exactly one operator')
    op, value = next(iter(node.items()))
    if op in ('literal', 'variable', 'values'):
        return deepcopy(node)
    if op == 'function':
        raise UnsupportedExpression('existing canonical calls require independent validation')
    if op == 'concat':
        if not isinstance(value, list) or len(value) < 2:
            raise UnsupportedExpression('concat requires at least two arguments')
        arguments, options = value, {}
    elif op == 'regex_capture':
        if not isinstance(value, dict) or set(value) != {'pattern', 'value'} or not isinstance(value['pattern'], str):
            raise UnsupportedExpression('regex_capture requires pattern and value')
        arguments, options = [value['value']], {'pattern': value['pattern']}
    elif op == 'merge':
        if not isinstance(value, dict) or set(value) != {'delimiter', 'sort', 'order', 'values'}:
            raise UnsupportedExpression('merge requires exact existing operands and options')
        arguments = [value['values']]
        options = {name: value[name] for name in ('delimiter', 'sort', 'order')}
    elif op == 'unique':
        arguments, options = [value], {}
    else:
        raise UnsupportedExpression(f'unrecognized legacy function: {op}')
    return {'function': {'name': op, 'arguments': [canonical_expression(arg) for arg in arguments],
                         'options': options}}


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
    if name == 'concat' and len(args) >= 2 and not options:
        return {'concat': [legacy_expression(a) for a in args]}
    if name == 'regex_capture' and len(args) == 1 and set(options) == {'pattern'}:
        return {'regex_capture': {'pattern': options['pattern'], 'value': legacy_expression(args[0])}}
    if name == 'unique' and len(args) == 1 and not options:
        return {'unique': legacy_expression(args[0])}
    if name == 'merge' and len(args) == 1 and set(options) == {'delimiter', 'sort', 'order'}:
        return {'merge': {**deepcopy(options), 'values': legacy_expression(args[0])}}
    raise UnsupportedExpression(f'canonical call outside legacy migration subset: {name}')
