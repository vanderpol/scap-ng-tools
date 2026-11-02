"""Build current native Item/Test/flat-Object surfaces directly from metadata.

No previous-version grammar is constructed, flattened or rewritten. Source XSDs
supply field identities/types; approved native mappings supply authoring choices.
The public generator adds its current condition and recursive Set definitions.
"""
import xml.etree.ElementTree as ET
from v04_capability_source import (direct_global, immediate_payload_elements,
    source_datatypes, infer_item_name, infer_system_characteristics_schema)

ROOT_ID = 'https://scap-ng.dev/schema/v0.4.0/'
COMMON = ROOT_ID + 'capability-common.schema.json'
LANG = ROOT_ID + 'assessment-language.schema.json'
RESERVED = {'object', 'object_title', 'capability', 'collect', 'set', 'filters',
            'traversal', 'filesystem', 'for_each', 'foreach', 'behaviors'}


def parameter_schema(spec):
    literal = ({'$ref': COMMON + '#/$defs/' + spec['schema_ref']} if spec.get('schema_ref')
               else {'type': spec.get('type', 'string')})
    if not spec.get('schema_ref') and spec.get('enum'):
        literal['enum'] = list(spec['enum'])
    if spec.get('semantic_datatype') == 'version':
        # Pinned OVAL common DatatypeEnumeration/version: nonnegative integer
        # components separated by one non-digit character, not string order.
        literal['pattern'] = r'^[0-9]+(?:[^0-9][0-9]+)*$'
        literal['x-scap-ng-semantic-datatype'] = 'version'
    if spec.get('description'):
        literal['description'] = spec['description']
    variants = [literal]
    if spec.get('allow_variable', False):
        variants.append({'$ref': COMMON + '#/$defs/variable_reference'})
    if spec.get('nullable', False):
        variants.append({'type': 'null'})
    return literal if len(variants) == 1 else {'oneOf': variants}


def flat_object(mapping):
    native, capability = mapping['native'], mapping['capability']
    selectors = set(native.get('selector_map', {}).values())
    parameters = native.get('collection_parameters', {})
    if selectors & parameters.keys() or (selectors | parameters.keys()) & RESERVED or 'select' in selectors:
        raise ValueError(capability + ': flat Object property collision')
    alternatives = [set(fields) for fields in native.get('object_selector_alternatives', [])]
    if selectors and (not alternatives or any(not fields or not fields <= selectors for fields in alternatives)):
        raise ValueError(capability + ': invalid selector alternatives')
    required_parameters = {name for name, spec in parameters.items() if spec.get('required', False)}
    traversal = native.get('traversal_definition')
    if traversal is None and native.get('uses_file_traversal', False):
        traversal = 'file_traversal'
    filesystem = traversal in {'file_traversal', 'windows_file_traversal'}
    properties = {'object_title': {'type': ['string', 'null']}, 'capability': {'const': capability},
                  'for_each': {'$ref': COMMON + '#/$defs/foreach_binding'}}
    if filesystem:
        properties['filesystem'] = {'$ref': COMMON + '#/$defs/filesystem_scope'}
    if traversal:
        properties['traversal'] = {'$ref': COMMON + '#/$defs/' + traversal}
    properties['set'] = {'$ref': '#/$defs/native_set_expression'}
    # The public generator fills these slots with source-typed native selectors.
    properties.update({name: {} for name in selectors})
    properties.update({name: parameter_schema(spec) for name, spec in parameters.items()})
    variants = []
    if selectors:
        for fields in alternatives:
            excluded = selectors - fields
            # Listed selector combinations are exact. Required-only oneOf
            # branches overlap when one alternative contains another.
            forbidden = ({'anyOf': [{'required': [name]} for name in sorted(excluded | {'set'})]}
                         if excluded else {'required': ['set']})
            variants.append({'required': sorted(fields | required_parameters), 'not': forbidden})
    elif parameters:
        direct = {'not': {'required': ['set']}}
        if required_parameters:
            direct['required'] = sorted(required_parameters)
        else:
            direct['allOf'] = [{'anyOf': [{'required': [name]} for name in sorted(parameters)]}]
        variants.append(direct)
    variants.append({'required': ['set'], 'not': {'anyOf': [
        {'required': [name]} for name in sorted(selectors | parameters.keys() | {'for_each'})]}})
    foreach = ({'required': [], 'not': {'required': ['set']},
                'allOf': [{'anyOf': [{'required': sorted(fields)} for fields in alternatives]}]}
               if alternatives else False)
    rules = [{'if': {'required': ['for_each']}, 'then': foreach}]
    if filesystem and selectors:
        rules.append({'if': {'anyOf': [{'required': ['full_path']}, {'required': ['directory']}]},
                      'then': {'required': ['filesystem']}})
    return {'type': 'object', 'required': [], 'properties': properties,
            'additionalProperties': False, 'oneOf': variants, 'allOf': rules,
            'description': capability + ' native flat Object; legal selector and acquisition keys '
                           'are capability-defined. Generic select/collect wrappers are invalid.'}


def item_contract(mapping, definitions, characteristics):
    native, source = mapping['native'], mapping['source']
    state = immediate_payload_elements(direct_global(definitions, 'element', source['state']))
    item = immediate_payload_elements(direct_global(characteristics, 'element', infer_item_name(source)))
    overrides = native.get('field_datatypes', {})
    fields = {}
    def add(source_name, name):
        if source_name not in item:
            raise KeyError('missing collected Item field ' + source_name)
        node = item[source_name]
        typed = {'allOf': [{'$ref': ROOT_ID + 'result-types.schema.json#/$defs/typed_value'},
            {'type': 'object', 'properties': {'datatype': {
                'type': 'string', 'enum': sorted(set(overrides.get(name) or source_datatypes(node)))}}}]}
        fields[name] = {'type': 'array', 'items': typed} if node.get('maxOccurs') not in (None, '1') else typed
    for source_name, name in native.get('state_field_map', {}).items():
        if source_name not in state:
            raise KeyError('missing source State field ' + source_name)
        add(source_name, name)
    for source_name, spec in native.get('native_added_state_fields', {}).items():
        add(source_name, spec.get('native_name', source_name))
    for source_name, name in native.get('item_only_field_map', {}).items():
        if source_name not in native.get('item_only_complex_fields', {}):
            raise ValueError('Item-only field requires a reviewed justification: ' + source_name)
        add(source_name, name)
    for key, constraint in (('item_value_types', 'type'), ('item_value_enums', 'enum')):
        for name, value in native.get(key, {}).items():
            if name not in fields or (constraint == 'type' and value not in {'string', 'boolean', 'integer', 'number'}) or (constraint == 'enum' and not value):
                raise ValueError('invalid Item value constraint: ' + name)
            target = fields[name].get('items', fields[name])
            target['allOf'].append({'properties': {'value': {constraint: list(value) if constraint == 'enum' else value}}})
    for name, description in native.get('field_documentation', {}).items():
        if name not in fields:
            raise ValueError('documentation references unknown Item field: ' + name)
        fields[name]['description'] = description
    return {'allOf': [{'$ref': ROOT_ID + 'collected-item.schema.json'},
        {'type': 'object', 'properties': {'capability': {'const': mapping['capability']},
         'fields': {'type': 'object', 'properties': dict(sorted(fields.items())), 'additionalProperties': False}}}]}


def native_surface(mapping, repo_root):
    """Return the native surface and its parsed Definitions XSD (at most 2 parses)."""
    source, native, capability = mapping['source'], mapping['native'], mapping['capability']
    definitions = ET.parse(repo_root / source['definitions_schema']).getroot()
    direct_global(definitions, 'element', source['test'])
    fixed = native.get('fixed_result') is not None
    required = ['capability', 'require', 'test_title']
    properties = {'test_title': {'type': ['string', 'null']},
                  'reported_elements': {'$ref': ROOT_ID + 'reported-elements.schema.json'},
                  'capability': {'const': capability},
                  'require': {'$ref': LANG + '#/$defs/test/properties/require'}}
    test = {'type': 'object', 'required': required, 'properties': properties,
            'additionalProperties': False, 'allOf': []}
    defs = {'test': test}
    if not fixed:
        required.append('reported_elements')
        input_spec = native.get('test_source', {'kind': 'object', 'field': 'object'})
        kind = input_spec.get('kind', 'object')
        if kind not in {'object', 'variable', 'none'}:
            raise ValueError(capability + ': unknown native Test source kind: ' + str(kind))
        field = input_spec.get('field', kind)
        if kind != 'none':
            required.append(field)
            properties[field] = ({'oneOf': [{'$ref': COMMON + '#/$defs/object_reference'},
                                            {'$ref': '#/$defs/object'}]} if kind == 'object'
                                 else {'type': 'string', 'minLength': 1})
            if kind == 'variable':
                properties[field]['pattern'] = '^[a-z0-9]+(?:-[a-z0-9]+)*-variable$'
        characteristics = ET.parse(repo_root / (source.get('system_characteristics_schema') or
            infer_system_characteristics_schema(source['definitions_schema']))).getroot()
        defs['collected_item'] = item_contract(mapping, definitions, characteristics)
        if kind == 'object':
            direct_global(definitions, 'element', source['object'])
            defs['object'] = flat_object(mapping)
        # Preserve the previously emitted inert guard for exact contract parity.
        # Normative current Test validation rejects these properties outright;
        # this guard does not introduce an authoring alias or native State layer.
        test['allOf'].append({'if': {'properties': {'states': {'type': 'array', 'minItems': 2}},
                                  'required': ['states']}, 'then': {'required': ['states_match']}})
        test['not'] = {'anyOf': [{'required': ['existence']}, {'required': ['match']}]}
    required.sort()
    test['allOf'].append({'$ref': LANG + '#/$defs/test'})
    result = {'$schema': 'https://json-schema.org/draft/2020-12/schema',
              '$id': ROOT_ID + 'generated/capabilities/' + capability + '.schema.json',
              'title': 'Generated SCAP-NG capability fragment: ' + capability,
              'x-semantic-validator-rules': mapping.get('semantic_validator_rules', []), '$defs': defs}
    if fixed:
        result['x-fixed-result'] = native['fixed_result']
    return result, definitions
