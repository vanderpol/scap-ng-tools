"""Translate closed string Variable graphs within an approved enum consumer."""
from copy import deepcopy
from v04_direct_scap_source import digest, ensure, native_identifier


def variable_datatype(visitor, identifier, active=None):
    """Derive a native Variable datatype from its expression.

    SCAP-NG 0.4.1 deliberately removed declaration-level ``datatype``. Enum
    projection is a closed string graph, so it may validate only typed
    literals, references, and unique populations without adding a cast.
    """
    active = set() if active is None else active
    ensure(identifier not in active, 'cyclic enum Variable graph')
    declaration = visitor.variables.get(identifier)
    ensure(isinstance(declaration, dict), 'unresolved enum Variable')
    active.add(identifier)
    expression = declaration.get('expression', {})
    if set(expression) == {'literal'}:
        value = expression['literal']
        datatype = value.get('datatype') if isinstance(value, dict) else None
    elif set(expression) == {'variable'}:
        datatype = variable_datatype(visitor, expression['variable'], active)
    elif set(expression) == {'unique'}:
        components = expression['unique'] if isinstance(expression['unique'], list) else [expression['unique']]
        types = {expression_datatype(visitor, component, active) for component in components}
        datatype = next(iter(types)) if len(types) == 1 else None
    else:
        datatype = None
    active.remove(identifier)
    return datatype


def expression_datatype(visitor, expression, active=None):
    if set(expression) == {'literal'}:
        value = expression['literal']
        return value.get('datatype') if isinstance(value, dict) else None
    if set(expression) == {'variable'}:
        return variable_datatype(visitor, expression['variable'], active)
    if set(expression) == {'unique'}:
        components = expression['unique'] if isinstance(expression['unique'], list) else [expression['unique']]
        types = {expression_datatype(visitor, item, active) for item in components}
        return next(iter(types)) if len(types) == 1 else None
    return None


def constant_string_values(node):
    expression = node.get('expression', {})
    ensure(set(expression) == {'literal'}, 'malformed enum constant Variable')
    payload = expression['literal']
    if isinstance(payload, dict):
        ensure(payload.get('datatype') == 'string',
               'enum selector Variable requires string datatype')
        values = payload.get('value')
    else:
        values = payload
    values = values if isinstance(values, list) else [values]
    ensure(values and all(isinstance(value, str) for value in values),
           'malformed enum constant Variable')
    return values


def validate_identity_enum_variable(visitor, name, domain):
    """Validate closed string graphs without renaming values or declarations."""
    active = set()
    checked = set()

    def literal(value):
        ensure(isinstance(value, str) and value in domain,
               'enum selector requires known supported values')

    def expression(node):
        if set(node) == {'literal'}:
            value = node['literal']
            ensure(isinstance(value, dict) and set(value) == {'datatype', 'value'}
                   and value['datatype'] == 'string', 'enum selector Variable requires string literals')
            payload = value['value']
            for item in (payload if isinstance(payload, list) else [payload]):
                literal(item)
        elif set(node) == {'variable'}:
            variable(node['variable'])
        elif set(node) == {'unique'}:
            components = node['unique'] if isinstance(node['unique'], list) else [node['unique']]
            ensure(components, 'enum selector Variable requires a non-empty unique graph')
            for component in components:
                expression(component)
        else:
            ensure(False, 'enum selector Variable requires a closed literal/reference/unique graph')

    def variable(identifier):
        ensure(identifier not in active, 'cyclic enum selector Variable graph')
        if identifier in checked:
            return
        active.add(identifier)
        node = visitor.variables[identifier]
        ensure(variable_datatype(visitor, identifier) == 'string', 'enum selector Variable requires string datatype')
        if node['kind'] == 'constant':
            for value in constant_string_values(node):
                literal(value)
        else:
            ensure(node['kind'] == 'local', 'unsupported enum selector Variable kind')
            expression(node['expression'])
        active.remove(identifier)
        checked.add(identifier)

    ensure(bool(domain), 'enum selector requires a closed value domain')
    variable(name)


def closed_enum_variable(visitor, identifier, aliases):
    """Clone existing typed expressions; leave generic consumers unchanged.

    Only literals, Variable references and unique commute with a bijective
    value-domain rename. Acquisition, casts and other functions stay outside
    this closed representation. No runtime mapping function is introduced.
    """
    ensure(aliases and len(set(aliases.values())) == len(aliases),
           'enum Variable requires a bijective value domain')
    original = visitor.named_variable(identifier)
    domain_hash = digest(aliases)
    suffix = '-enum-' + domain_hash[:8] + '-variable'
    active = set()
    source_ids = {native_identifier(visitor.source.node(visitor.component_id, ident, 'variable'), 'variable'): ident
                  for ident, record in visitor.used.items() if record['kind'] == 'variable'}

    def rename(value):
        ensure(isinstance(value, str) and value in aliases,
               'unsupported enum comparison/value in closed Variable')
        return aliases[value]

    def expression(node):
        if set(node) == {'literal'}:
            value = node['literal']
            ensure(isinstance(value, dict) and set(value) == {'datatype', 'value'}
                   and value['datatype'] == 'string', 'enum Variable cast outside closed literal proof')
            payload = value['value']
            renamed = [rename(item) for item in (payload if isinstance(payload, list) else [payload])]
            return {'literal': {**value, 'value': renamed if isinstance(payload, list) else renamed[0]}}
        if set(node) == {'variable'}:
            return {'variable': variable(node['variable'])}
        if set(node) == {'unique'}:
            components = node['unique'] if isinstance(node['unique'], list) else [node['unique']]
            ensure(components, 'runtime enum Variable requires a non-empty unique graph')
            translated = [expression(component) for component in components]
            return {'unique': translated if len(translated) > 1 else translated[0]}
        ensure(False, 'runtime enum Variable requires an approved alias-domain projection or closed literal graph')

    def variable(name):
        target = name.removesuffix('-variable') + suffix
        cache_key = name, domain_hash
        if cache_key in visitor.enum_variable_copies:
            return visitor.enum_variable_copies[cache_key]
        ensure(target not in visitor.variables, 'enum Variable identity collision')
        ensure(name not in active, 'cyclic enum Variable graph')
        active.add(name)
        source = visitor.variables[name]
        ensure(variable_datatype(visitor, name) == 'string', 'enum Variable cast outside closed literal proof')
        result = deepcopy(source)
        if source['kind'] == 'constant':
            payload = source['expression']['literal']
            values = constant_string_values(source)
            renamed = [rename(value) for value in values]
            if isinstance(payload, dict):
                result['expression'] = {'literal': {
                    **payload, 'value': renamed if isinstance(payload.get('value'), list)
                    else renamed[0]}}
            else:
                result['expression'] = {'literal': renamed}
        else:
            ensure(source['kind'] == 'local', 'unsupported enum Variable kind')
            result['expression'] = expression(source['expression'])
        active.remove(name)
        visitor.variables[target] = result
        visitor.enum_variable_copies[cache_key] = target
        visitor.enum_variable_equivalences.append({'source_variable': source_ids[name],
            'source_native_variable': name, 'native_variable': target, 'aliases': dict(aliases)})
        return target

    return {'variable': variable(original)}
