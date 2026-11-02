"""Translate closed string Variable graphs within an approved enum consumer."""
from copy import deepcopy
from v04_direct_scap_source import digest, ensure, native_identifier


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
            literal(value['value'])
        elif set(node) == {'variable'}:
            variable(node['variable'])
        elif set(node) == {'unique'}:
            expression(node['unique'])
        else:
            ensure(False, 'enum selector Variable requires a closed literal/reference/unique graph')

    def variable(identifier):
        ensure(identifier not in active, 'cyclic enum selector Variable graph')
        if identifier in checked:
            return
        active.add(identifier)
        node = visitor.variables[identifier]
        ensure(node['datatype'] == 'string', 'enum selector Variable requires string datatype')
        if node['kind'] == 'constant':
            ensure(set(node['expression']) == {'literal'} and
                   isinstance(node['expression']['literal'], list), 'malformed enum constant Variable')
            for value in node['expression']['literal']:
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
            return {'literal': {**value, 'value': rename(value['value'])}}
        if set(node) == {'variable'}:
            return {'variable': variable(node['variable'])}
        if set(node) == {'unique'}:
            return {'unique': expression(node['unique'])}
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
        ensure(source['datatype'] == 'string', 'enum Variable cast outside closed literal proof')
        result = deepcopy(source)
        if source['kind'] == 'constant':
            ensure(set(source['expression']) == {'literal'}
                   and isinstance(source['expression']['literal'], list), 'malformed enum constant Variable')
            result['expression'] = {'literal': [rename(v) for v in source['expression']['literal']]}
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
