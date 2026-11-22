"""Bounded, explicit XCCDF export -> Parameter -> Assessment Input drafting."""
from v04_direct_scap_source import XCCDF, OVAL, attributes, ensure, native_identifier, digest, xml_identity, local_name
from v04_direct_datatypes import SOURCE_TYPES, native_datatype, comparison
from v04_draft_compatibility import DECISION


OVAL_COMPARISONS = {
    'equals': 'equals', 'not equal': 'not_equal', 'pattern match': 'matches_regex',
    'case insensitive equals': 'case_insensitive_equals',
    'case insensitive not equal': 'case_insensitive_not_equal',
    'less than': 'less_than', 'less than or equal': 'less_than_or_equal',
    'greater than': 'greater_than', 'greater than or equal': 'greater_than_or_equal',
    'subset of': 'subset_of', 'superset of': 'superset_of',
    'bitwise and': 'bitwise_and', 'bitwise or': 'bitwise_or',
}
RESTRICTION_OPERATORS = {'AND': 'and', 'OR': 'or', 'ONE': 'one', 'XOR': 'xor'}
MAX_CONSTRAINT_DEPTH = 32
MAX_CONSTRAINT_NODES = 256


def _external_cardinality(visitor, identifier):
    nodes = visitor.source.nodes.get(visitor.component_id, {})
    objects = {node.get('id'): node for node in nodes.values()
               if local_name(node).endswith('_object')}
    # Only consumers in the selected Definition/Test closure can determine
    # this Input's cardinality.  Sibling Tests in the same standalone XML are
    # independent source documents for conversion purposes and must not make a
    # valid selected closure fail with a spurious cardinality conflict.
    selected_tests = {source_id for source_id, used in visitor.used.items()
                      if used.get('kind') == 'test'}
    selected_tests.update(identifier for kind, identifier in visitor.active
                          if kind == 'test')
    ensure(selected_tests, 'external Variable has no selected Test consumer')
    uses = []
    for test in nodes.values():
        if test.get('id') not in selected_tests or not local_name(test).endswith('_test'):
            continue
        for child in test:
            if local_name(child) != 'object' or not child.get('object_ref'):
                continue
            obj = objects.get(child.get('object_ref'))
            if obj is None or local_name(obj) != 'variable_object':
                continue
            refs = [node.text.strip() for node in obj
                    if local_name(node) == 'var_ref' and (node.text or '').strip()]
            if identifier in refs:
                uses.append({'source_test': test.get('id'),
                             'check_existence': test.get('check_existence', 'at_least_one_exists')})
    ensure(uses, 'external Variable has no supported consumer-derived cardinality')
    cards = {'at_least_one_exists': 'one_or_more', 'only_one_exists': 'exactly_one',
             'any_exist': 'zero_or_more', 'none_exist': 'zero_or_more'}
    result = {cards.get(row['check_existence']) for row in uses}
    ensure(None not in result and len(result) == 1,
           'external Variable consumers require conflicting/unsupported cardinality')
    return result.pop(), uses


def _restriction_expression(visitor, group, source_type, depth=1, counter=None):
    counter = counter if counter is not None else [0]
    ensure(depth <= MAX_CONSTRAINT_DEPTH, 'external Variable restriction expression exceeds depth limit')
    counter[0] += 1
    ensure(counter[0] <= MAX_CONSTRAINT_NODES, 'external Variable restriction expression exceeds node limit')
    attributes(group, {'hint', 'operator'})
    ensure(not (group.text or '').strip() and group.get('operator', 'AND') in RESTRICTION_OPERATORS,
           'malformed external Variable restriction group')
    leaves = []
    for restriction in group:
        attributes(restriction, {'operation'})
        ensure(local_name(restriction) == 'restriction' and not len(restriction),
               'malformed external Variable restriction')
        operation = restriction.get('operation')
        ensure(operation in OVAL_COMPARISONS and (restriction.text or '').strip(),
               'unsupported external Variable restriction operation')
        leaves.append({comparison(source_type, operation, OVAL_COMPARISONS[operation]):
                       visitor.literal(source_type, restriction.text or '')})
    ensure(leaves, 'external Variable restriction requires one or more predicates')
    if len(leaves) == 1:
        return leaves[0], counter
    return {RESTRICTION_OPERATORS[group.get('operator', 'AND')]: leaves}, counter


def _external_constraints(visitor, element, source_type):
    allowed, groups = [], []
    for child in element:
        if local_name(child) == 'possible_value':
            attributes(child, {'hint'})
            ensure(not len(child) and (child.text or '').strip(), 'malformed external Variable possible_value')
            allowed.append(visitor.literal(source_type, child.text or ''))
        elif local_name(child) == 'possible_restriction':
            expression, _ = _restriction_expression(visitor, child, source_type)
            groups.append(expression)
        else:
            ensure(False, 'unsupported external Variable child: ' + local_name(child))
    # OVAL external_variable permits an empty restriction population.  In that
    # case the declaration's datatype and the consumer-derived cardinality are
    # the complete contract: the invocation must bind the Input, but no
    # fixture/default or invented predicate may be introduced.  This matters
    # for standalone Definitions that mix unrestricted external Variables with
    # the restricted possible_value/possible_restriction witnesses.
    constraints = {}
    if allowed:
        constraints['allowed'] = allowed
    if groups:
        constraints['predicate'] = groups[0] if len(groups) == 1 else {'or': groups}
    return constraints


def _value_satisfies_constraints(value, constraints):
    def expr(node):
        if 'and' in node: return all(expr(child) for child in node['and'])
        if 'or' in node: return any(expr(child) for child in node['or'])
        if 'one' in node: return sum(expr(child) for child in node['one']) == 1
        if 'xor' in node: return sum(expr(child) for child in node['xor']) % 2 == 1
        operation, bound = next((key, value) for key, value in node.items() if key != 'datatype')
        if operation == 'equals': return value == bound
        if operation == 'not_equal': return value != bound
        if operation == 'case_insensitive_equals': return isinstance(value, str) and value.casefold() == str(bound).casefold()
        if operation == 'case_insensitive_not_equal': return isinstance(value, str) and value.casefold() != str(bound).casefold()
        if operation == 'matches_regex':
            import re
            return isinstance(value, str) and isinstance(bound, str) and re.fullmatch(bound, value) is not None
        if operation in {'greater_than', 'greater_than_or_equal', 'less_than', 'less_than_or_equal'}:
            return {'greater_than': value > bound, 'greater_than_or_equal': value >= bound,
                    'less_than': value < bound, 'less_than_or_equal': value <= bound}[operation]
        raise ValueError('unsupported Input restriction operation at binding time: ' + operation)
    alternatives = [value == allowed for allowed in constraints.get('allowed', [])]
    if 'predicate' in constraints:
        alternatives.append(expr(constraints['predicate']))
    return not alternatives or any(alternatives)


XCCDF_RELATIONS = {
    'less than': 'less_than',
    'less than or equal': 'less_than_or_equal',
    'greater than': 'greater_than',
    'greater than or equal': 'greater_than_or_equal',
}


def _relation_satisfied(value, operator, bound):
    if type(value) is bool or type(bound) is bool:
        return False
    return {'less_than': value < bound,
            'less_than_or_equal': value <= bound,
            'greater_than': value > bound,
            'greater_than_or_equal': value >= bound}[operator]


def source_disambiguated_identifier(visitor, element, suffix, peers):
    """Keep readable names unless source descriptors actually collide.

    XCCDF Values and OVAL external Variables are globally benchmark-scoped,
    while their titles/comments are not identities.  Add a deterministic
    source-ID token only for duplicate descriptors so shared uses of the same
    source node retain the original native name.
    """
    identifier = native_identifier(element, suffix)
    descriptors = [native_identifier(peer, suffix) for peer in peers]
    if descriptors.count(identifier) <= 1:
        return identifier
    token = digest(element.get('id'))[:10]
    stem = identifier.removesuffix('-' + suffix)
    budget = 64 - len(suffix) - len(token) - 2
    ensure(budget >= 1, 'native source discriminator exceeds identifier budget')
    return stem[:budget].rstrip('-') + '-' + token + '-' + suffix


def value_parameter_identifier(visitor, value):
    nodes = visitor.source.nodes.get(visitor.source.benchmark_component, {})
    peers = [node for node in nodes.values() if node.tag == '{' + XCCDF + '}Value']
    return source_disambiguated_identifier(visitor, value, 'parameter', peers)


def external_input_identifier(visitor, element):
    nodes = visitor.source.nodes.get(visitor.component_id, {})
    peers = [node for node in nodes.values() if local_name(node) == 'external_variable']
    return source_disambiguated_identifier(visitor, element, 'input', peers)


def check_exports(source, rule):
    mappings=[]
    for check in rule.findall('{'+XCCDF+'}check'):
        if check.get('system') != OVAL:
            continue
        exports={}
        for node in check.findall('{'+XCCDF+'}check-export'):
            attributes(node, {'value-id','export-name'})
            variable,value=node.get('export-name'),node.get('value-id')
            ensure(variable and value and variable not in exports and not len(node), 'ambiguous/malformed check-export')
            target=source.nodes[source.benchmark_component].get(value)
            ensure(target is not None and target.tag=='{'+XCCDF+'}Value', 'unresolved check-export Value')
            exports[variable]=target
        mappings.append(exports)
    ensure(not mappings or all({k:digest(xml_identity(v)) for k,v in m.items()} ==
        {k:digest(xml_identity(v)) for k,v in mappings[0].items()} for m in mappings),
        'conflicting default/automated check-export bindings')
    return mappings[0] if mappings else {}


def external_input(visitor, element):
    recovery = getattr(visitor, 'native_recovery', False)
    ident = element.get('id')
    value = visitor.bound_exports.get(ident)
    # Standalone OVAL has no XCCDF check-export. It still emits a typed,
    # required native Input contract; caller-supplied bindings are intentionally
    # resolved by RI at execution time, never by this converter or a fixture.
    standalone = value is None
    if not standalone:
        attributes(value, {'id','type','operator','interactive','interfaceHint','hidden'})
        allowed_names = ['title', 'description', 'value', 'reference']
        if recovery:
            allowed_names.append('warning')
        allowed_children = {'{' + XCCDF + '}' + name for name in allowed_names}
        ensure(all(n.tag in allowed_children for n in value),
               'XCCDF Value constraints require a supported Parameter adapter')
        if recovery:
            for warning in value.findall('{' + XCCDF + '}warning'):
                attributes(warning, {'category', '{http://www.w3.org/XML/1998/namespace}lang'})
                ensure(not len(warning), 'complex XCCDF warning is unsupported')
    datatype = element.get('datatype')
    source_type = value.get('type', 'string') if value is not None else datatype
    if standalone:
        ensure(datatype in SOURCE_TYPES, 'unsupported external Variable datatype')
    else:
        ensure(source_type == {'string': 'string', 'boolean': 'boolean', 'int': 'int', 'float': 'float'}.get(datatype),
               'check-export source/Variable datatype mismatch')
    cardinality, consumers = _external_cardinality(visitor, ident)
    defaults = ([node for node in value.findall('{' + XCCDF + '}value') if not node.get('selector')]
                if value is not None else [])
    if value is not None:
        ensure(len(defaults) <= 1 and all(not len(node) for node in value.findall('{' + XCCDF + '}value')),
               'ambiguous/complex XCCDF default')
    input_id = external_input_identifier(visitor, element) if recovery else native_identifier(element, 'input')
    parameter_id = (value_parameter_identifier(visitor, value) if recovery else native_identifier(value, 'parameter')) if value is not None else None
    contract = {'datatype': native_datatype(datatype), 'cardinality': cardinality,
                'required': True, 'description': (value.findtext('{' + XCCDF + '}description', '') if value is not None else element.get('comment', ''))}
    constraints = _external_constraints(visitor, element, datatype)
    contract['constraints'] = constraints
    visitor.inputs[input_id] = contract
    if value is not None:
        parameter = {'id': parameter_id, 'datatype': native_datatype(datatype), 'cardinality': 'one',
                     'required': True, 'resolution': 'publisher' if defaults else 'organization',
                     'title': value.findtext('{' + XCCDF + '}title', ''), 'description': contract['description'],
                     'constraints': constraints}
        if defaults:
            parameter['value'] = visitor.literal(datatype, defaults[0].text or '')
            ensure(_value_satisfies_constraints(parameter['value'], constraints),
                   'publisher default violates external Variable restrictions')
        visitor.policy_parameters[parameter_id] = parameter
        visitor.input_bindings[input_id] = {'parameter': parameter_id}
    visitor.conversion_warnings.append({
        'code': 'native_standalone_external_input' if standalone else ('native_input_binding_unproved' if recovery else 'check_export_binding_unproved'),
        'owner_decision': ('https://github.com/scap-ng/issues/8#issuecomment-6587857027' if recovery else DECISION),
        'source_external_variable': ident, 'source_variable_sha256': digest(xml_identity(element)),
        'source_value': value.get('id') if value is not None else None,
        'source_value_sha256': digest(xml_identity(value)) if value is not None else None,
        'source_value_xml': xml_identity(value) if value is not None else None,
        'input': input_id, 'parameter': parameter_id, 'resolution': 'invocation' if standalone else parameter['resolution'],
        'cardinality': cardinality, 'cardinality_consumers': consumers,
        'restriction_semantics': 'possible_value and possible_restriction alternatives are ORed; every supplied value is checked',
        'independent_static_proof': 'UNPROVED', 'scanner_runtime': 'NOT_RUN',
        'message': ('Standalone external Variable lowered to an explicit required Input; no fixture/default was bound.' if standalone else
                    'Explicit typed native 0.4 Input/Parameter restriction binding retained; policy/runtime equivalence independently unproved.'),
    })
    return {'input': input_id}
