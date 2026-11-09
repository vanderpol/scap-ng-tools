#!/usr/bin/env python3
"""Fresh direct-0.4 experiment: pinned SCAP -> an explicitly partial automated subset.

Conversion uses current capability metadata, not old NG renderers or IRs.
Public validation, compilation and independent proof are separate commands.
"""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import re
import time
import zipfile

from v04_direct_scap_source import (
    SourceModel, UnsupportedSource, OVAL, XCCDF, attributes, digest, ensure,
    local_name, native_identifier, xml_identity,
)

from v04_direct_datatypes import SOURCE_TYPES, SPECIAL_TYPES, native_datatype, literal, comparison

ROOT = Path(__file__).resolve().parents[1]
SUPPORT = json.loads(Path(__file__).with_name('v04_direct_capabilities.json').read_text())
CAPABILITIES = tuple(SUPPORT['enabled'])
ensure(SUPPORT['specification_version'] == '0.4.0' and len(CAPABILITIES) == len(set(CAPABILITIES)),
       'invalid direct capability activation registry')
EXISTENCE = {'at_least_one_exists': 'one_or_more', 'none_exist': 'none',
             'only_one_exists': 'exactly_one', 'any_exist': 'zero_or_more'}
FIELD_EXISTENCE = {**EXISTENCE, 'all_exist': 'every'}
MATCHING = {'all': 'every', 'at least one': 'one_or_more', 'none satisfy': 'none', 'only one': 'exactly_one'}
COMPARISONS = {'equals': 'equals', 'not equal': 'not_equal', 'pattern match': 'matches_regex',
               'case insensitive equals': 'case_insensitive_equals', 'less than': 'less_than',
               'greater than': 'greater_than', 'greater than or equal': 'greater_than_or_equal',
               'less than or equal': 'less_than_or_equal',
               'case insensitive not equal': 'case_insensitive_not_equal',
               'subset of': 'subset_of', 'superset of': 'superset_of',
               'bitwise and': 'bitwise_and', 'bitwise or': 'bitwise_or'}
SET_OPERATORS = {'UNION': 'union', 'INTERSECTION': 'intersection', 'COMPLEMENT': 'difference'}


def load_mappings():
    mappings = [json.loads((ROOT / f'schema/v0.4.0/capability-mappings/supported/{name}.json').read_text())
                for name in CAPABILITIES]
    ensure(all(mapping['specification_version'] == '0.4.0' for mapping in mappings), 'mapping version mismatch')
    ensure(all((mapping['source']['namespace'].rsplit('#', 1)[-1] in ('independent', 'linux', 'unix', 'windows') or
                mapping['capability'] in {'solaris.smf', 'iosxe.line', 'iosxe.global'})
               for mapping in mappings), 'capability outside approved direct-converter scope')
    return mappings


def logical_condition(operator, children):
    ensure(operator in ('AND', 'OR', 'ONE', 'XOR') and children, f'unsupported/empty logical operator: {operator}')
    # A sole AND/OR operand preserves all six results; no two-valued rewrites.
    return children[0] if len(children) == 1 and operator in ('AND', 'OR') else {operator.lower(): children}


class AssessmentConverter:
    """One typed recursive visitor per component/Assessment, with explicit caches.

    References return native dictionaries/literal arrays, never an intermediate
    representation. `used` is external provenance; other containers are native
    declarations. Cached values are copied so a consumer cannot mutate a peer.
    """
    def __init__(self, source, component_id, mappings, *, canonical_variable_functions=False,
                 human_compact=True, preserve_variable_references=False):
        self.source, self.component_id, self.mappings = source, component_id, mappings
        # Opt-in migration probe only. Production output and source-proof paths
        # retain their current syntax until coordinated compiler migration.
        self.canonical_variable_functions = canonical_variable_functions
        # Opt-in authoring projection; a new program digest needs fresh review.
        self.human_compact = human_compact
        # Standalone language qualification retains source identities and alias
        # edges; existing STIG conversion keeps its reviewed folding/names.
        self.preserve_variable_references = preserve_variable_references
        self.human_compaction = []
        self.active, self.cache, self.used = set(), {}, {}
        self.native_names = {}
        self.tests, self.variables, self.shared_objects = {}, {}, {}
        self.enum_projection_cache = {}
        self.object_uses = None
        self.selector_equivalences = []
        self.enum_variable_copies = {}
        self.enum_variable_equivalences = []
        self.conversion_warnings = []
        self.bound_exports, self.inputs, self.policy_parameters, self.input_bindings = {}, {}, {}, {}

    def capability(self, element, kind):
        matches = [mapping for mapping in self.mappings if element.tag ==
                   f'{{{mapping["source"]["namespace"]}}}{mapping["source"].get(kind)}']
        ensure(len(matches) == 1, f'unsupported {kind} capability: {element.tag}')
        return matches[0]

    def native_name(self, element, suffix, title=None):
        if self.preserve_variable_references:
            title = element.get('id')
        identifier = native_identifier(element, suffix, title)
        # Resolve ambiguous source comments from source semantics, before the
        # first reference is allocated. Cache only the immutable node index;
        # SourceModel.index replaces that index and invalidates this cache.
        nodes = getattr(self.source, 'nodes', {}).get(self.component_id, {})
        if nodes and not self.preserve_variable_references and suffix in ('object', 'test', 'variable'):
            from collections import Counter
            cache = getattr(self.source, '_native_name_census', {})
            entry = cache.get((self.component_id, suffix))
            if entry is None or entry[0] is not nodes:
                peers = [n for n in nodes.values() if local_name(n).endswith('_' + suffix)]
                counts = Counter(native_identifier(n, suffix) for n in peers)
                entry = (nodes, counts); cache[(self.component_id, suffix)] = entry
                self.source._native_name_census = cache
            if entry[1][identifier] > 1:
                values = [(n.text or '').strip() for n in element.iter()
                          if not len(n) and (n.text or '').strip()]
                controls = [value for n in element.iter() if n is not element
                            for key, value in sorted(n.attrib.items())
                            if key not in ('id', 'version', 'comment') and not key.endswith('_ref')]
                if values:
                    # The shortened ambiguous comment lost distinguishing
                    # targets. Name the source kind, controls and target instead.
                    identifier = native_identifier(element, suffix,
                        ' '.join([local_name(element), *controls, *values]))
        key = suffix, identifier
        original = element.get('id')
        ensure(isinstance(original, str) and original, 'source node lacks identity for native naming')
        ensure(key not in self.native_names or self.native_names[key] == original,
               f'native {suffix} name collision {identifier}: {self.native_names.get(key)} vs {original}')
        self.native_names[key] = original
        return identifier

    def reference(self, identifier, kind):
        if self.object_uses is None:
            self.object_uses = self.source.object_uses(self.component_id, identifier, kind)
        key = kind, identifier
        ensure(key not in self.active, f'cyclic {kind} dependency: {identifier}')
        if key in self.cache:
            return deepcopy(self.cache[key])
        element = self.source.node(self.component_id, identifier, kind)
        permitted = {'definition': {'class'}, 'test': {'check', 'check_existence', 'state_operator'},
                     'object': set(), 'state': {'operator'}, 'variable': {'datatype'}}
        attributes(element, {'id', 'version', 'comment'} | permitted[kind])
        if kind in ('definition', 'variable'):
            ensure(element.tag.startswith(f'{{{OVAL}}}'), 'Definition/Variable namespace mismatch')
        self.active.add(key)
        self.used[identifier] = {'kind': kind, 'sha256': digest(xml_identity(element))}
        tokens=[]
        def datatype_tokens(node,path=()):
            if 'datatype' in node.attrib:
                tokens.append({'path':list(path),'qname':node.tag,'token':node.get('datatype'),
                               'entity_sha256':digest(xml_identity(node))})
            for i,child in enumerate(node):datatype_tokens(child,(*path,i))
        datatype_tokens(element)
        if tokens:self.used[identifier]['original_datatype_tokens']=tokens
        try:
            result = getattr(self, 'convert_' + kind)(element)
            self.cache[key] = result
            return deepcopy(result)
        finally:
            self.active.remove(key)

    def convert_definition(self, element):
        criteria = element.findall(f'{{{OVAL}}}criteria')
        ensure(len(criteria) == 1, 'one Definition criteria boundary required')
        return self.criteria(criteria[0])

    def criteria(self, element):
        attributes(element, {'operator', 'comment', 'negate'})
        ensure(element.get('negate', 'false') in ('true', 'false'), 'unsupported negate lexical')
        children = []
        for child in element:
            if child.tag == f'{{{OVAL}}}criteria':
                value = self.criteria(child)
            else:
                kind = {'criterion': 'test', 'extend_definition': 'definition'}.get(local_name(child))
                ensure(kind and child.tag == f'{{{OVAL}}}{local_name(child)}', 'unsupported criteria child')
                attributes(child, {kind + '_ref', 'comment', 'negate'})
                value = self.reference(child.get(kind + '_ref'), kind)
                ensure(child.get('negate', 'false') in ('true', 'false'), 'unsupported negate lexical')
                if child.get('negate') == 'true':
                    value = {'not': value}
            children.append(value)
        value = logical_condition(element.get('operator', 'AND'), children)
        return {'not': value} if element.get('negate') == 'true' else value

    def convert_test(self, element):
        mapping = self.capability(element, 'test')
        if mapping['native'].get('fixed_result') is not None:
            ensure(mapping['native']['fixed_result'] == 'unknown' and
                   mapping['native'].get('test_source', {}).get('kind') == 'none' and not len(element),
                   'unsupported fixed-result Test shape')
            ensure(element.get('check') in MATCHING and
                   element.get('check_existence', 'at_least_one_exists') in set(EXISTENCE) | {'all_exist'},
                   'invalid fixed-result source controls')
            # OVAL unknown_test always returns unknown; its required legacy
            # count attributes do not govern that result. The approved native
            # grammar still requires this uniform structured requirement.
            identifier = self.native_name(element, 'test')
            self.tests[identifier] = {'test_title': element.get('comment', ''), 'capability': mapping['capability'],
                'require': {'item_requirement': {'items_found': 'one_or_more'}},
                'reported_elements': 'all'}
            return {'test': identifier}
        objects = element.findall(f'{{{mapping["source"]["namespace"]}}}object')
        ensure(len(objects) == 1, 'one Test Object required')
        conditions = []
        for child in element:
            kind = local_name(child)
            ensure(kind in ('object', 'state') and child.tag == f'{{{mapping["source"]["namespace"]}}}{kind}', 'Test child namespace/shape')
            attributes(child, {kind + '_ref'})
            ensure(not len(child), 'Test reference has children')
            if kind == 'state':
                self.same_family(child.get('state_ref'), 'state', mapping)
                conditions.append(self.reference(child.get('state_ref'), 'state'))
        found = element.get('check_existence', 'at_least_one_exists')
        draft_all_exist = found == 'all_exist' and getattr(self.source, 'draft_compatibility', False)
        ensure(found in EXISTENCE or draft_all_exist, f'unsupported Test existence: {found}')
        requirement = {'items_found': 'one_or_more' if draft_all_exist else EXISTENCE[found]}
        if conditions:
            ensure(element.get('check') in MATCHING and found != 'none_exist', 'unsupported Test matching/absence combination')
            requirement.update(items_satisfying=MATCHING[element.get('check')])
            requirement.update(logical_condition(element.get('state_operator', 'AND'), conditions))
            if self.human_compact:
                from v04_human_authoring_compact import compact_test_requirement
                compacted, edit = compact_test_requirement(requirement)
                if edit:
                    self.human_compaction.append({'source_test': element.get('id'), **edit})
                    requirement = compacted
        object_id = objects[0].get('object_ref')
        from v04_direct_authoring_contract import test_requirement
        requirement = test_requirement(requirement)
        self.same_family(object_id, 'object', mapping)
        acquisition = self.reference(object_id, 'object')
        if isinstance(acquisition, dict):
            acquisition.pop('capability')  # Test inheritance; Variable/private Objects keep their own capability.
        identifier = self.native_name(element, 'test')
        self.tests[identifier] = {'test_title': element.get('comment', ''), 'capability': mapping['capability'],
                                  'object': acquisition, 'require': requirement, 'reported_elements': 'all'}
        if draft_all_exist:
            from v04_draft_compatibility import all_exist_warning
            self.conversion_warnings.append(all_exist_warning(self.source, self.component_id, element,
                self.source.node(self.component_id, object_id, 'object'), identifier))
        if mapping['native'].get('test_source', {}).get('kind') == 'none':
            # The version-local contract deliberately omits meaningless source
            # singleton Objects. The source dependency remains in provenance.
            ensure(acquisition == {}, 'singleton system source must have no acquisition parameters')
            self.tests[identifier].pop('object')
        elif mapping['native'].get('test_source', {}).get('kind') == 'variable':
            ensure(set(acquisition) == {'variable'}, 'Variable Test source cannot carry acquisition modifiers')
            self.tests[identifier]['variable'] = acquisition['variable']
            self.tests[identifier].pop('object')
        return {'test': identifier}

    def same_family(self, identifier, kind, mapping):
        node = self.source.node(self.component_id, identifier, kind)
        ensure(self.capability(node, kind)['capability'] == mapping['capability'], f'{kind} capability mismatch: {identifier}')

    def convert_state(self, element):
        from v04_direct_system_policy import policy_entity
        mapping = self.capability(element, 'state')
        conditions, seen = [], set()
        for child in element:
            field = local_name(child)
            ensure(child.tag.startswith(f'{{{mapping["source"]["namespace"]}}}') and
                   field in mapping['native']['state_field_map'], 'unsupported State field/namespace')
            ensure(field not in seen, 'repeated State field outside bounded proof')
            seen.add(field)
            if mapping['capability'] == 'windows.fileeffectiverights':
                types = tuple(mapping['native']['field_datatypes'][mapping['native']['state_field_map'][field]])
                datatype = {('string',): 'string', ('boolean',): 'boolean'}.get(types)
                # Original EntityStateBoolType requires explicit datatype;
                # the String type permits the string default. Never infer bool.
                ensure(datatype and child.get('datatype', 'string') == datatype,
                       'file-rights State field requires original datatype ' + str(datatype))
            conditions.append({'fields': {mapping['native']['state_field_map'][field]:
                                          self.predicate(policy_entity(child, mapping), mapping)}})
        condition = logical_condition(element.get('operator', 'AND'), conditions)
        if self.human_compact:
            from v04_human_authoring_compact import compact_source_state
            compacted, edit = compact_source_state(condition)
            if edit:
                self.human_compaction.append({'source_state': element.get('id'), **edit})
                return compacted
        return condition

    def convert_object(self, element):
        from v04_direct_scalar_behaviors import behavior_routes, scalar_behaviors, split_behaviors
        mapping = self.capability(element, 'object')
        acquisition = {'capability': mapping['capability']}
        if mapping['native'].get('test_source', {}).get('kind') == 'variable':
            references = element.findall(f'{{{mapping["source"]["namespace"]}}}var_ref')
            ensure(len(element) == len(references) == 1, 'Variable source requires one var_ref; Sets/Filters unsupported')
            attributes(references[0], set())
            ensure(not len(references[0]), 'Variable source var_ref has children')
            acquisition['variable'] = self.named_variable((references[0].text or '').strip())
            return acquisition
        if mapping['native'].get('test_source', {}).get('kind') == 'none':
            ensure(not len(element), 'singleton system source cannot have selectors, Sets or Filters')
            return acquisition
        sets = element.findall(f'{{{OVAL}}}set')
        if sets:
            ensure(len(element) == 1, 'Set cannot mix with leaf acquisition or direct Filters')
            acquisition['set'] = self.set_expression(sets[0], mapping)
        else:
            selectors = mapping['native'].get('selector_map', {})
            parameters = mapping['native'].get('collection_parameter_source_map', {})
            filters = []
            behaviors = None
            for child in element:
                if child.tag == f'{{{OVAL}}}filter':
                    filters.append(self.filter(child, mapping))
                    continue
                field = local_name(child)
                if field == 'behaviors' and (mapping['capability'] in (
                        'independent.textfilecontent', 'independent.shellcommand') or
                        mapping['native'].get('traversal_definition') in ('file_traversal', 'windows_file_traversal', 'hierarchy_traversal') or
                        behavior_routes(mapping)):
                    ensure(child.tag == f'{{{mapping["source"]["namespace"]}}}behaviors' and behaviors is None,
                           'duplicate/foreign acquisition behaviors')
                    behaviors = child
                    continue
                ensure(child.tag.startswith(f'{{{mapping["source"]["namespace"]}}}') and
                       field in selectors.keys() | parameters.keys(), f'unsupported Object field: {field}')
                target = selectors.get(field, parameters.get(field))
                ensure(target not in acquisition, 'duplicate Object field')
                if mapping['capability'] == 'windows.cmdlet':
                    from v04_direct_cmdlet_inputs import cmdlet_input
                    acquisition[target] = cmdlet_input(child, mapping['native']['collection_parameters'][target],
                        lambda entity: self.predicate(entity, mapping, selector=True), self.parameter)
                else:
                    if field in selectors:
                        acquisition[target] = self.predicate(child, mapping, selector=True)
                    else:
                        operations = ('equals',)
                        if mapping['capability'] == 'independent.shellcommand' and field == 'pattern':
                            # This field already denotes a regex acquisition input,
                            # not a predicate over the command or returned Items.
                            operations = tuple(op for op in mapping['native'].get(
                                'collection_parameter_source_operations', {}).get(field, ())
                                if op in ('equals', 'pattern match'))
                        acquisition[target] = self.parameter(child, operations=operations)
                if (field in selectors and child.get('operation') == 'case insensitive equals'
                        and 'equals' in acquisition[target]):
                    self.selector_equivalences.append({'source_object': element.get('id'),
                        'source_selector': {'tag': child.tag, 'attributes': dict(child.attrib), 'value': child.text},
                        'native_selector': target,
                        'native_comparator': 'equals', 'reason': 'closed Registry hive domain equality',
                        'source_contract': 'OVAL 5.12.3 EntityObjectRegistryHiveType/EntityItemRegistryHiveType'})
            for path, value in mapping.get('migration_crosswalk', {}).get('materialized_defaults', {}).items():
                ensure(path.startswith('behaviors.'), 'unrecognized acquisition default')
                source = path.split('.')[1]
                acquisition[behavior_routes(mapping).get(source, source)] = value
            if mapping['capability'] == 'independent.yamlfilecontent':
                from v04_direct_yaml_records import yaml_acquisition
                yaml_acquisition(acquisition, behaviors)
            scalar_part, traversal_part = behaviors, behaviors
            if behavior_routes(mapping) and mapping['native'].get('traversal_definition') in (
                    'file_traversal', 'windows_file_traversal', 'hierarchy_traversal'):
                traversal_fields = ({'max_depth', 'recurse_direction'}
                    if mapping['native']['traversal_definition'] == 'hierarchy_traversal' else
                    {'max_depth', 'recurse', 'recurse_direction', 'recurse_file_system'})
                scalar_part, traversal_part = split_behaviors(behaviors, behavior_routes(mapping),
                    traversal_fields)
            if behavior_routes(mapping):
                acquisition.update(scalar_behaviors(scalar_part, mapping))
            if mapping['capability'] == 'independent.textfilecontent':
                from v04_direct_file_behaviors import file_behaviors, textfile_path_controls
                text_part, traversal_part = split_behaviors(behaviors,
                    {'ignore_case', 'multiline', 'singleline', 'item_creation'},
                    {'max_depth', 'recurse', 'recurse_direction', 'recurse_file_system'})
                textfile_path_controls(traversal_part, acquisition)
                acquisition.update(file_behaviors(text_part))
            if mapping['capability'] == 'independent.shellcommand':
                from v04_direct_command_behaviors import command_behaviors
                acquisition.update(command_behaviors(behaviors))
            if mapping['native'].get('traversal_definition') in ('file_traversal', 'windows_file_traversal'):
                # FileBehaviors defaults recurse_file_system to all, including
                # exact full_path acquisition. Sets inherit it on each leaf.
                if 'content' not in acquisition:
                    from v04_direct_file_behaviors import traversal_behaviors
                    acquisition.update(traversal_behaviors(traversal_part, acquisition,
                        windows=mapping['native']['traversal_definition'] == 'windows_file_traversal',
                        selector_map=mapping['native'].get('selector_map', {})))
                if 'content' not in acquisition:
                    acquisition.setdefault('filesystem', 'all')
            if mapping['native'].get('traversal_definition') == 'hierarchy_traversal':
                from v04_direct_file_behaviors import hierarchy_behaviors
                acquisition.update(hierarchy_behaviors(traversal_part, acquisition))
            if filters:
                acquisition['filters'] = filters
        # Source identity, not payload equality, determines shared acquisitions.
        if self.object_uses[element.get('id')] > 1:
            title = self.object_title(element, mapping)
            identifier = self.native_name(element, 'object', title=title)
            acquisition['object_title'] = title
            self.shared_objects[identifier] = acquisition
            return identifier
        return acquisition

    def object_title(self, element, mapping):
        """Describe source acquisition facts, never infer an unstated purpose."""
        comment = (element.get('comment') or '').strip()
        def words(value):
            return ' '.join(value.lower().replace('.', ' ').replace('_', ' ').replace('-', ' ').split())
        generic = {words(mapping['capability']), words(mapping['capability'] + ' object'),
                   words(mapping['capability'] + ' acquisition'), words(local_name(element))}
        if comment and words(comment) not in generic:
            return comment
        details = []
        described_fields = (mapping['native'].get('selector_map', {}).keys() |
                            mapping['native'].get('collection_parameter_source_map', {}).keys())
        for child in element:
            if local_name(child) in described_fields:
                value = 'from a source Variable' if child.get('var_ref') else repr(child.text or '')
                details.append(f'{local_name(child)} {child.get("operation", "equals")} {value}')
        ensure(details, 'shared acquisition has no source-grounded title')
        return local_name(element).removesuffix('_object').replace('_', ' ').capitalize() + ': ' + '; '.join(details)

    def set_expression(self, element, mapping):
        attributes(element, {'set_operator'})
        operator = element.get('set_operator', 'UNION')
        ensure(operator in SET_OPERATORS, f'unsupported Set operator: {operator}')
        nested = element.findall(f'{{{OVAL}}}set')
        references = element.findall(f'{{{OVAL}}}object_reference')
        filters = element.findall(f'{{{OVAL}}}filter')
        ensure(bool(nested) != bool(references), 'Set must contain nested Sets or Object references, not both')
        ensure(1 <= len(nested or references) <= 2, 'OVAL Set arity outside 1..2')
        ensure(len(element) == len(nested) + len(references) + len(filters) and not (nested and filters), 'unsupported Set child/filter placement')
        operands = []
        if nested:
            operands = [{'set': self.set_expression(child, mapping)} for child in nested]
        else:
            predicates = [self.filter(child, mapping) for child in filters]
            for reference in references:
                attributes(reference, set())
                ensure(not len(reference), 'object_reference has children')
                identifier = (reference.text or '').strip()
                self.same_family(identifier, 'object', mapping)
                # OVAL applies each ordered Filter to EACH operand before the
                # operator. A root post-Set Filter would change that boundary.
                acquisition = self.reference(identifier, 'object')
                if isinstance(acquisition, dict):
                    acquisition.pop('capability')  # Inherit down this same-family Set boundary.
                operands.append({'object': acquisition, 'filters': deepcopy(predicates)})
        return {'operator': SET_OPERATORS[operator], 'operands': operands}

    def filter(self, element, mapping):
        attributes(element, {'action'})
        ensure(not len(element), 'Filter must reference a State')
        action = element.get('action', 'exclude')
        ensure(action in ('include', 'exclude'), f'unsupported Filter action: {action}')
        identifier = (element.text or '').strip()
        self.same_family(identifier, 'state', mapping)
        return {action: self.filter_condition(self.reference(identifier, 'state'))}

    def filter_condition(self, condition):
        # The approved Filter grammar names a single field directly; Test
        # conditions use a `fields` leaf. Quantifiers and logical boundaries
        # are identical. Render this typed condition, never arbitrary records.
        if 'fields' in condition:
            fields = condition['fields']
            ensure(bool(fields), 'Filter requires at least one field')
            # Presentation compaction can combine a single source State's
            # scalar AND into one fields map. Filter grammar still needs one
            # named field per leaf: restore the explicit AND, without changing
            # source operators, field quantifiers or record boundaries.
            if len(fields) > 1:
                return {'and': [{name: predicate} for name, predicate in fields.items()]}
            return fields
        operator, children = next(iter(condition.items()))
        return {operator: [self.filter_condition(child) for child in children]}

    def convert_variable(self, element):
        datatype = element.get('datatype')
        ensure(datatype in SOURCE_TYPES, f'unsupported Variable datatype: {datatype}')
        if local_name(element)=='external_variable' and getattr(self.source,'draft_compatibility',False):
            from v04_draft_inputs import external_input
            return external_input(self,element)
        if local_name(element) == 'constant_variable':
            ensure(len(element) and all(child.tag == f'{{{OVAL}}}value' and not child.attrib and not len(child) for child in element), 'malformed constant Variable')
            # Immutable source constants become typed expected arrays. Keep the
            # consumer's var_check separately; never infer it from array length.
            return [self.literal(datatype, child.text or '') for child in element]
        ensure(local_name(element) == 'local_variable' and len(element) == 1, 'external/malformed Variable unsupported')
        identifier = self.native_name(element, 'variable')
        expression = self.function(element[0])
        if self.canonical_variable_functions:
            from v04_variable_function_migration import canonical_expression
            expression = canonical_expression(expression)
        self.variables[identifier] = {'kind': 'local', 'datatype': native_datatype(datatype),
                                      'expression': expression}
        return {'variable': identifier}

    def named_variable(self, source_id):
        """Keep constant collections named when a source/function consumes them.

        Scalar predicate constants still use the existing inline-array form;
        Test sources and multivalue function inputs need a first-class Variable.
        No values, Cartesian products or collection statuses are evaluated here.
        """
        ensure(not self.renamed_enum_projection(source_id),
               'renamed enum projection requires a matching enum consumer')
        value = self.reference(source_id, 'variable')
        if isinstance(value, list):
            element = self.source.node(self.component_id, source_id, 'variable')
            identifier = self.native_name(element, 'variable')
            datatype = element.get('datatype')
            self.variables[identifier] = {'kind': 'constant',
                'datatype': native_datatype(datatype),
                'expression': {'literal': value}}
            return identifier
        ensure('variable' in value, 'Assessment Input cannot replace a named runtime Variable source')
        return value['variable']

    def function(self, element):
        ensure(element.tag.startswith(f'{{{OVAL}}}'), 'function namespace mismatch')
        operation = local_name(element)
        if operation == 'literal_component':
            attributes(element, {'datatype'})
            ensure(not len(element), 'literal_component has children')
            return {'literal': {'datatype': native_datatype(element.get('datatype', 'string')),
                                'value': self.literal(element.get('datatype', 'string'), element.text or '')}}
        if operation == 'variable_component':
            attributes(element, {'var_ref'})
            ensure(not len(element), 'variable_component has children')
            if self.preserve_variable_references:
                return {'variable': self.named_variable(element.get('var_ref'))}
            value = self.reference(element.get('var_ref'), 'variable')
            ensure(not isinstance(value,dict) or 'input' not in value,
                   'Assessment Input function composition requires a supported typed expression')
            if isinstance(value, list):
                variable = self.source.node(self.component_id, element.get('var_ref'), 'variable')
                # A complete one-value constant is a scalar function operand;
                # no dynamic status or multi-value product boundary is erased.
                if variable.get('datatype') == 'string' and len(value) == 1:
                    return {'literal': {'datatype': 'string', 'value': value[0]}}
                return {'variable': self.named_variable(element.get('var_ref'))}
            ensure(not len(element) and isinstance(value, dict), 'constant array function needs Cartesian proof')
            return value
        if operation == 'object_component':
            attributes(element, {'object_ref', 'item_field'})
            ensure(not len(element), 'object_component has children')
            identifier = element.get('object_ref')
            mapping = self.capability(self.source.node(self.component_id, identifier, 'object'), 'object')
            if mapping['native'].get('test_source', {}).get('kind') == 'variable':
                ensure(element.get('item_field') == 'value', 'Variable source has only a value projection')
                return {'variable': self.reference(identifier, 'object')['variable']}
            ensure(mapping['native'].get('test_source', {}).get('kind') != 'none',
                   'singleton system source has no approved Variable Object acquisition')
            ensure(element.get('item_field') in mapping['native']['state_field_map'], 'unknown object_component field')
            return {'values': {'object': self.reference(identifier, 'object'),
                               'field': mapping['native']['state_field_map'][element.get('item_field')]}}
        ensure(operation in ('concat', 'regex_capture', 'merge', 'unique'), f'unsupported function: {operation}')
        attributes(element, {'pattern'} if operation == 'regex_capture' else
                   {'delimiter', 'sort', 'order'} if operation == 'merge' else set())
        ensure(len(element) and (operation != 'regex_capture' or (len(element) == 1 and 'pattern' in element.attrib)), 'function arity/pattern')
        values = [self.function(child) for child in element]
        if operation in ('merge', 'unique'):
            # Existing native aggregation consumes one collection expression.
            # Do not invent a union grammar for multiple source components.
            ensure(len(values) == 1, 'multiple aggregation components need an approved collection expression')
            if operation == 'unique':
                return {'unique': values[0]}
            ensure(element.get('sort', 'document') in ('document', 'lexical', 'numeric', 'natural')
                   and element.get('order', 'ascending') in ('ascending', 'descending'), 'unsupported merge sort/order')
            return {'merge': {'delimiter': element.get('delimiter', ''), 'sort': element.get('sort', 'document'),
                              'order': element.get('order', 'ascending'), 'values': values[0]}}
        ensure(operation != 'concat' or len(values) >= 2, 'concat requires at least two components')
        return {'concat': values} if operation == 'concat' else {'regex_capture': {'pattern': element.get('pattern'), 'value': values[0]}}

    # Retained visitor API; lexical conversion has one reusable implementation.
    literal = staticmethod(literal)

    def operand(self, element, *, enum_aliases=None):
        if element.get('var_ref'):
            variable = self.source.node(self.component_id, element.get('var_ref'), 'variable')
            # Cross-datatype OVAL casts can produce error/unknown results; do
            # not silently infer a target type from a literal array's values.
            ensure(variable.get('datatype') == element.get('datatype', 'string'), 'Variable cast outside bounded proof')
            if self.preserve_variable_references:
                ensure(enum_aliases is None, 'standalone enum projection outside qualified scope')
                return {'variable': self.named_variable(element.get('var_ref'))}
            if self.renamed_enum_projection(element.get('var_ref')):
                ensure(enum_aliases is not None, 'renamed enum projection requires a matching enum consumer')
                self.enum_variable(element.get('var_ref'), enum_aliases)
            return self.reference(element.get('var_ref'), 'variable')
        return self.literal(element.get('datatype', 'string'), element.text or '')

    def parameter(self, element, *, operations=('equals',)):
        attributes(element, {'datatype', 'operation', 'var_ref', 'var_check'})
        ensure(not len(element) and element.get('datatype', 'string') == 'string' and
               element.get('operation', 'equals') in operations, 'unsupported acquisition parameter comparison/type')
        value = self.operand(element)
        if isinstance(value, list):
            # One immutable value is a single invocation input. Multiple values
            # need a source-backed acquisition rule, not an implicit fan-out.
            ensure(len(value) == 1 and element.get('var_check', 'all') in ('all', 'at least one', 'only one'),
                   'multivalue/complement acquisition parameter requires an approved expansion rule')
            return value[0]
        ensure('var_check' not in element.attrib or (element.get('var_ref') and
               element.get('var_check') == 'all'), 'acquisition parameter var_check outside bounded proof')
        ensure(isinstance(value, (str, dict)), 'array acquisition parameter unsupported')
        return value

    def renamed_enum_projection(self, identifier, active=None):
        """Detect a renamed value domain before a generic string consumer.

        Field-name projection also changes enum values. It is safe inside a
        proved enum comparison, but not inside arbitrary string concatenation,
        command parameters or direct Variable Tests without an inverse adapter.
        Cache source facts only; consumer approval is checked on every use.
        """
        if identifier in self.enum_projection_cache:
            return self.enum_projection_cache[identifier]
        active = set() if active is None else active
        ensure(identifier not in active, f'cyclic variable dependency: {identifier}')
        active.add(identifier)
        variable = self.source.node(self.component_id, identifier, 'variable')
        renamed = False
        for node in variable.iter():
            if node.tag == f'{{{OVAL}}}variable_component':
                renamed |= self.renamed_enum_projection(node.get('var_ref'), active)
            elif node.tag == f'{{{OVAL}}}object_component':
                obj = self.source.node(self.component_id, node.get('object_ref'), 'object')
                mapping = self.capability(obj, 'object')
                field = node.get('item_field')
                crosswalk = mapping['native'].get('state_value_crosswalk', {}).get(field)
                renamed |= bool(crosswalk)
        active.remove(identifier)
        self.enum_projection_cache[identifier] = renamed
        return renamed

    def enum_variable(self, identifier, aliases, active=None):
        """Return a typed reference in this consumer's approved enum domain.

        Closed literal/reference/unique graphs get separate translated copies,
        preserving their original generic string uses. Renamed Item fields
        already project native values, so matching-domain runtime projections
        need no rewriting. Arbitrary runtime strings and other functions still
        require a source-preserving adapter; never invent an input convention.
        """
        if not self.renamed_enum_projection(identifier):
            from v04_direct_enum_variables import closed_enum_variable
            return closed_enum_variable(self, identifier, aliases)
        active = set() if active is None else active
        ensure(aliases and len(set(aliases.values())) == len(aliases),
               'runtime enum Variable requires a bijective alias-domain projection')
        ensure(identifier not in active, 'cyclic enum Variable')
        active.add(identifier)
        variable = self.source.node(self.component_id, identifier, 'variable')
        ensure(local_name(variable) == 'local_variable' and variable.get('datatype') == 'string'
               and len(variable) == 1, 'runtime enum Variable requires an approved alias-domain projection')

        def expression(node):
            name = local_name(node)
            if name == 'variable_component':
                return self.enum_variable(node.get('var_ref'), aliases, active)
            if name == 'unique' and len(node) == 1:
                return expression(node[0])
            ensure(name == 'object_component',
                   'runtime enum Variable requires an approved alias-domain projection')
            obj = self.source.node(self.component_id, node.get('object_ref'), 'object')
            mapping = self.capability(obj, 'object')
            source_field = node.get('item_field')
            crosswalk = mapping['native'].get('state_value_crosswalk', {}).get(source_field)
            field = mapping['native']['state_field_map'].get(source_field)
            domain = mapping['native'].get('state_value_enums', {}).get(field, [])
            declared = mapping.get('migration_crosswalk', {}).get(crosswalk, {})
            ensure(domain and {k: v for k, v in declared.items() if v in domain} == aliases,
                   'runtime enum Variable requires an approved alias-domain projection')
        expression(variable[0])
        active.remove(identifier)
        return {'variable': self.native_name(variable, 'variable')}

    def record_predicate(self, element, mapping):
        """Preserve a complete record before combining its named field results."""
        attributes(element, {'datatype', 'operation', 'entity_check', 'check_existence'})
        ensure(element.get('operation', 'equals') == 'equals', 'unsupported record comparator')
        found = element.get('check_existence', 'at_least_one_exists')
        matching = element.get('entity_check', 'all')
        ensure(found in FIELD_EXISTENCE and found != 'none_exist' and matching in MATCHING,
               'record absence/quantifier outside bounded source proof')
        ensure(len(element) and not (element.text or '').strip(), 'record requires named fields')
        fields, source_names = {}, set()
        for child in element:
            name = child.get('name')
            ensure(child.tag == f'{{{OVAL}}}field' and name and name not in source_names
                   and not any('A' <= c <= 'Z' for c in name), 'invalid/duplicate original record field')
            source_names.add(name)
            if mapping['capability'] == 'independent.yamlfilecontent':
                from v04_direct_yaml_records import yaml_record_key
                name = yaml_record_key(name)
                ensure(name not in fields, 'duplicate decoded YAML record key')
            fields[name] = self.predicate(child, mapping, record_field=True)
        # Member lookup is inside this record: missing required members remain
        # errors. Field-value cardinality does not turn lookup failure into an
        # empty successful record, or borrow a value from another record.
        return {'record': {'records_found': FIELD_EXISTENCE[found], 'records_matching': MATCHING[matching],
                           'fields': fields}}

    def predicate(self, element, mapping, selector=False, *, record_field=False):
        nil = '{http://www.w3.org/2001/XMLSchema-instance}nil'
        if selector and nil in element.attrib:
            allowed = {nil, 'datatype'}
            # OVAL nil filename selects directory Items. Explicit default
            # equality preserves that selection; other operations stay strict.
            if mapping['capability'] == 'unix.file' and local_name(element) == 'filename':
                allowed.add('operation')
                ensure(element.get('operation', 'equals') == 'equals', 'unsupported nil filename comparator')
            attributes(element, allowed)
            field = mapping['native'].get('selector_map', {}).get(local_name(element))
            ensure(field in mapping['native'].get('nullable_selectors', ('name',)) and
                   element.get(nil) in ('true', '1') and not len(element) and not (element.text or '').strip(),
                   'unsupported nil selector')
            datatype = 'int' if mapping['native']['field_datatypes'][field] == ['integer'] else 'string'
            # Original EntityObjectIntType requires explicit datatype=int;
            # EntityObjectStringType alone permits its omitted fixed string type.
            ensure(element.get('datatype', 'string' if datatype == 'string' else None) == datatype,
                   'nil selector datatype mismatch')
            return None
        if element.get('datatype') == 'record':
            ensure(not selector and not record_field, 'nested/selector record outside source grammar')
            return self.record_predicate(element, mapping)
        attributes(element, {'datatype', 'operation', 'var_ref', 'var_check'} |
                   ({'name', 'entity_check'} if record_field else set() if selector else {'entity_check', 'check_existence'}))
        ensure(not len(element), 'record/nested entity unsupported')
        existence = element.get('check_existence', 'at_least_one_exists')
        if existence == 'none_exist':
            ensure(not selector and set(element.attrib) == {'check_existence'} and not element.text, 'comparator-bearing absence blocked')
            return {'values_found': 'none'}
        operation = element.get('operation', 'equals')
        ensure(existence in FIELD_EXISTENCE and operation in COMPARISONS, 'unsupported entity existence/comparator')
        if operation == 'case insensitive not equal':
            ensure(element.get('datatype', 'string') == 'string', 'case-insensitive inequality requires string datatype')
        if operation in ('greater than', 'greater than or equal', 'less than or equal') and element.get('datatype', 'string') not in SPECIAL_TYPES:
            ensure(element.get('datatype') == 'int', 'ordered comparison expansion requires integer source datatype')
        crosswalk = mapping['native'].get('selector_value_crosswalk' if selector else 'state_value_crosswalk', {}).get(local_name(element))
        field = mapping['native']['state_field_map'].get(local_name(element))
        domain = mapping['native'].get('state_value_enums', {}).get(field, [])
        aliases = dict(mapping['migration_crosswalk'][crosswalk]) if crosswalk else {}
        if (not selector and mapping['capability'] == 'windows.ntuser' and field == 'type'
                and '' in domain and mapping['migration_crosswalk'].get('source_defect_corrections', {}).get(
                    'legacy_empty_registry_type_state')):
            # The approved State domain explicitly preserves this lexical value.
            # It is not a new collected Item type or an absence predicate.
            aliases[''] = ''
        enum_aliases = ({k: v for k, v in aliases.items() if v in domain}
                        if crosswalk and operation in ('equals', 'not equal') else None)
        value = self.operand(element, enum_aliases=enum_aliases)
        if isinstance(value,dict) and 'input' in value:
            ensure(not selector and not crosswalk,'Assessment Input acquisition/enum projection outside supported expected-value binding')
        native_enum_variable = False
        if crosswalk:
            if operation == 'not equal' and not selector:
                # Equality and inequality are invariant under a bijection of
                # the complete enum domain. Lexical/regex operations are not.
                renamed_domain = {k: v for k, v in aliases.items() if v in domain}
                ensure(renamed_domain and len(set(renamed_domain.values())) == len(renamed_domain),
                       'unsupported enum comparison/value')
            elif operation != 'equals':
                # Original Object/Item hives are a closed, case-distinct domain.
                # The independent XSD relation proof covers every pair (including
                # the empty error placeholder). Only nonempty literal acquisition
                # selectors are admitted; States and dynamic operands stay strict.
                enumeration = mapping['native'].get('selector_value_enums', {}).get(local_name(element), [])
                domain = {k: v for k, v in aliases.items() if v in enumeration}
                ensure(selector and mapping['capability'] == 'windows.registry' and local_name(element) == 'hive'
                       and operation == 'case insensitive equals' and element.get('datatype', 'string') == 'string'
                       and not element.get('var_ref') and isinstance(value, str) and value in domain
                       and len({k.casefold() for k in domain}) == len(domain)
                       and len(set(domain.values())) == len(domain), 'unsupported enum comparison/value')
                operation = 'equals'
            # Static Variables retain their ordered values (including duplicates)
            # and the consumer's independent var_check. A crosswalk renames each
            # value; it must not turn the collection into OR or collapse it.
            if isinstance(value, dict):
                field = mapping['native']['state_field_map'].get(local_name(element))
                domain = mapping['native'].get('state_value_enums', {}).get(field, [])
                value = self.enum_variable(element.get('var_ref'), {k: v for k, v in aliases.items() if v in domain})
                native_enum_variable = True
            else:
                expected = value if isinstance(value, list) else [value]
                ensure(all(isinstance(v, str) and v in aliases for v in expected),
                       'unsupported enum comparison/value')
                renamed = [aliases[v] for v in expected]
                value = renamed if isinstance(value, list) else renamed[0]
        if selector:
            field = mapping['native'].get('selector_map', {}).get(local_name(element))
            enumeration = mapping['native'].get('selector_value_enums', {}).get(field)
            if enumeration:
                ensure(operation == 'equals', 'unsupported enum selector comparator')
                if isinstance(value, dict) and not native_enum_variable and not crosswalk:
                    from v04_direct_enum_variables import validate_identity_enum_variable
                    ensure(set(value) == {'variable'}, 'unsupported enum selector operand')
                    validate_identity_enum_variable(self, value['variable'], enumeration)
                    native_enum_variable = True
                expected = value if isinstance(value, list) else [value]
                ensure(native_enum_variable or all(isinstance(v, str) and v in enumeration for v in expected),
                       'enum selector requires known supported values')
        if not selector:
            native_field = mapping['native']['state_field_map'].get(local_name(element))
            enumeration = mapping['native'].get('state_value_enums', {}).get(native_field)
            if enumeration and operation != 'pattern match':
                expected = value if isinstance(value, list) else [value]
                ensure(native_enum_variable or all(isinstance(v, str) and v in enumeration for v in expected),
                       'unsupported enum comparison/value')
            elif enumeration:
                # Regex expected values need not be enum members. This path
                # has no value crosswalk: alias-domain patterns remain blocked
                # above, rather than being applied to renamed native values.
                ensure(element.get('datatype', 'string') == 'string', 'enum regex requires string datatype')
        result = {comparison(element.get('datatype', 'string'), operation, COMPARISONS[operation]): value}
        # YAML values, typed operation names and declared Variables/Inputs
        # express the complete source domain. Do not emit a second field tag.
        if element.get('var_ref'):
            ensure(element.get('var_check', 'all') in MATCHING, 'unsupported var_check')
            result['value_match'] = MATCHING[element.get('var_check', 'all')]
        if not selector:
            ensure(element.get('entity_check', 'all') in MATCHING, 'unsupported entity_check')
            result.update(values_found=FIELD_EXISTENCE[existence], values_matching=MATCHING[element.get('entity_check', 'all')])
        return result


def dependency_blockers(source, node, mappings):
    """Probe independent obligations even when an earlier sibling failed.

    Uses the same conversion primitives, never a second acceptance grammar.
    Unsupported capability internals remain unidentified, not guessed support.
    """
    from v04_direct_inventory import issue
    problems = []
    component, identifier, kind = node['component'], node['id'], node['kind']
    element = source.node(component, identifier, kind)

    def probe(label, method, *args):
        try:
            method(*args)
        except (UnsupportedSource, ValueError) as error:
            problem = issue(blocker_category(str(error)), str(error), identifier, component)
            problem['source_path'] = label
            problems.append(problem)

    visitor = AssessmentConverter(source, component, mappings)
    probe('closure', visitor.reference, identifier, kind)
    # Quantifier support is independent of which capability failed first.
    if kind == 'test':
        found = element.get('check_existence', 'at_least_one_exists')
        probe('@check_existence', ensure, found in EXISTENCE or
              (found == 'all_exist' and getattr(source, 'draft_compatibility', False)),
              f'unsupported Test existence: {found}')
    if kind in ('state', 'object'):
        try:
            mapping = visitor.capability(element, kind)
        except UnsupportedSource:
            return problems
        for number, child in enumerate(element):
            label, name = f'{child.tag}[{number}]', local_name(child)
            if kind == 'state':
                probe(label, visitor.predicate, child, mapping)
            elif name in mapping['native'].get('selector_map', {}):
                probe(label, visitor.predicate, child, mapping, True)
            elif name in mapping['native'].get('collection_parameter_source_map', {}):
                probe(label, visitor.parameter, child)
            if child.tag == '{' + OVAL + '}filter':
                probe(label, visitor.filter, child, mapping)
            if child.tag == '{' + OVAL + '}set':
                for nested in child.iter():
                    if nested.tag == '{' + OVAL + '}set':
                        probe(label, visitor.set_expression, nested, mapping)
                    elif nested.tag == '{' + OVAL + '}filter':
                        probe(label, visitor.filter, nested, mapping)
    if kind == 'variable' and local_name(element) == 'local_variable':
        for child in element.iter():
            if child is not element:
                probe(child.tag, visitor.function, child)
    return problems


def convert_rule(source, source_id, mappings, *, human_compact=True):
    """Convert one entire automated closure; failures leave no emitted artifacts."""
    documents = {}
    ensure(source_id in source.rules, f'source Rule not found: {source_id}')
    rule = source.rules[source_id]
    component, definition, omitted_checks = source.automated_check(rule)
    converter = AssessmentConverter(source, component, mappings, human_compact=human_compact)
    if getattr(source,'draft_compatibility',False):
        from v04_draft_inputs import check_exports
        converter.bound_exports=check_exports(source,rule)
    expression = converter.reference(definition, 'definition')
    title = rule.findtext(f'{{{XCCDF}}}title', '')
    # Local Assessments retain a human-recognizable source control discriminator.
    # These are not promoted/global shared-library names (Decision 11/12).
    control = re.search(r'SV-\d+', source_id)
    local_title = title + (' ' + control.group() if control else '')
    rule_id = native_identifier(rule, 'rule', local_title)
    assessment_id = native_identifier(rule, 'assessment', local_title)
    assessment = {'id': assessment_id, 'version': 1, 'assessment_title': title,
        'mode': 'automated', 'class': source.node(component, definition, 'definition').get('class'),
        'specification': {'id': 'scap-ng.pre-alpha.assessment', 'version': '0.4.0'}}
    for section in ('shared_objects', 'variables'):
        if getattr(converter, section):
            assessment[section] = getattr(converter, section)
    if converter.inputs:
        assessment['inputs']=converter.inputs
    assessment.update(tests=converter.tests, evaluate=expression)
    documents[f'authoring/direct-slice/assessments/{assessment_id}.json'] = {'assessment': assessment}
    # This is a compilation fixture, not a full Rule-policy renderer.
    native_rule = {'id': rule_id, 'version': rule.findtext(f'{{{XCCDF}}}version', ''), 'title': title,
        'severity': rule.get('severity', 'unknown'), 'role': 'full', 'weight': float(rule.get('weight', '1')),
        'discussion': rule.findtext(f'{{{XCCDF}}}description', ''), 'rationale': None,
        'extensions': {}, 'warnings': [], 'identifiers': [], 'references': [], 'requires': [], 'conflicts': [],
        'applicability': [], 'parameters': {}, 'remediation': {}, 'organizational_input_requirements': {},
        'assessment_choices': {'automated': {'assessment': assessment_id}}, 'default_assessment_choice': 'automated'}
    optional_metadata = ('discussion', 'rationale', 'extensions', 'warnings', 'identifiers', 'references', 'remediation')
    omitted_metadata = [key for key in optional_metadata if native_rule[key] in (None, '', [], {})]
    for key in omitted_metadata:
        native_rule.pop(key)
    documents[f'authoring/direct-slice/rules/{rule_id}.json'] = {'rule': native_rule}
    from scap_ng_tools.converter._v04_semantic.v04_input_presence import presence_contract
    from scap_ng_tools.authoring.input_discovery import validate_choice_map
    if converter.input_bindings:
        native_rule['assessment_choices']['automated']['inputs'] = converter.input_bindings
    # Validate all native Input consumers before emitting a Rule. The direct
    # converter has no author-supplied discovery map, so the packaged map is
    # always the exact compiler derivation (including the empty case).
    if converter.inputs or converter.input_bindings:
        presence_contract(assessment)
        parameters = {p['id']: p for p in converter.policy_parameters.values()}
        rows = validate_choice_map(assessment, converter.input_bindings, parameters)
        native_rule['organizational_input_requirements'] = {'automated': rows} if rows else {}
    binding = {'source_rule': source_id, 'source_rule_sha256': digest(xml_identity(rule)),
        'component': component, 'definition': definition, 'native_rule': rule_id, 'assessment': assessment_id,
        'dependencies': converter.used, 'omitted_checks': omitted_checks,
        'source_platforms': [child.get('idref') for child in rule.findall(f'{{{XCCDF}}}platform')]}
    binding['authoring_contract_migration'] = {'owner_decision_date': '2026-10-31',
        'decisions': [1, 3, 6, 10, 13, 14], 'requires_fresh_proof': True,
        'omitted_empty_optional_metadata': omitted_metadata,
        'native_identity_sources': [{'kind': kind, 'native_id': ident, 'source_id': original}
                                    for (kind, ident), original in sorted(converter.native_names.items())]}
    if converter.selector_equivalences:
        binding['selector_equivalences'] = converter.selector_equivalences
    if converter.enum_variable_equivalences:
        binding['enum_variable_equivalences'] = converter.enum_variable_equivalences
    if converter.human_compaction:
        # Explicitly separate presentation candidates from accepted source proofs.
        binding['human_authoring_compaction_review'] = converter.human_compaction
        binding['independent_static_proof_eligible'] = False
        binding['conversion_status'] = 'CONVERTED_UNVERIFIED'
    warnings = list(converter.conversion_warnings)
    for check in rule.findall(f'{{{XCCDF}}}check'):
        if check.get('system') != OVAL:
            continue
        for reference in check.findall(f'{{{XCCDF}}}check-content-ref'):
            warning = getattr(source, 'catalog_warnings', {}).get(reference.get('href'))
            if warning:
                warnings.append({**warning, 'definition': definition,
                    'definition_sha256': digest(xml_identity(source.node(component, definition, 'definition')))})
    if warnings:
        binding['conversion_warnings'] = list({digest(w): w for w in warnings}.values())
        binding['source_variable_context'] = {k: v for k, v in converter.used.items() if v['kind'] == 'variable'}
        binding['independent_static_proof_eligible'] = False
        binding['conversion_status'] = 'CONVERTED_UNVERIFIED'
    if converter.policy_parameters:
        binding['policy_parameters']=converter.policy_parameters
    return documents, binding


def convert(source: SourceModel, rule_ids: list[str], *, human_compact=True):
    """Strict focused API; any unsupported selection fails the entire request."""
    ensure(rule_ids and len(set(rule_ids)) == len(rule_ids), 'distinct source Rules required')
    mappings = load_mappings()
    documents, bindings = {}, []
    for source_id in rule_ids:
        native, binding = convert_rule(source, source_id, mappings, human_compact=human_compact)
        ensure(not set(native) & set(documents), 'native Rule/Assessment name collision in selected source Rules')
        documents.update(native)
        bindings.append(binding)
    return assemble_subset(source, documents, bindings, mappings)


def assemble_subset(source, documents, rule_trace, mappings):
    """Project selection only over emitted Rules; an empty subset has no package."""
    rule_ids = [row['source_rule'] for row in rule_trace]
    rule_links = {row['source_rule']: row['native_rule'] for row in rule_trace}
    benchmark = source.benchmark
    ensure(all(source.rule_selected(source.rules[identifier]) for identifier in rule_ids), 'disabled source defaults unsupported')
    profiles, profile_trace = [], []
    for profile in benchmark.findall(f'{{{XCCDF}}}Profile'):
        selection = {identifier: source.rule_selected(source.rules[identifier], profile) for identifier in rule_ids}
        identifier = native_identifier(profile, 'profile')
        profiles.append({'id': identifier, 'title': profile.findtext(f'{{{XCCDF}}}title'),
                         'disabled_rules': [rule_links[rule] for rule, enabled in selection.items() if not enabled]})
        profile_trace.append({'source_id': profile.get('id'), 'source_sha256': digest(xml_identity(profile)),
                              'native_id': identifier, 'selected': selection})
    wrapper = {'id': 'direct-slice', 'ng_schema_version': '0.4.0', 'use_case': 'compliance',
        'version': {'value': benchmark.findtext(f'{{{XCCDF}}}version', '')},
        'assessment_specifications': [{'id': 'scap-ng.pre-alpha.assessment', 'version': '0.4.0'}],
        'title': [{'text': '[AUTOMATED PROTOTYPE SUBSET] ' + benchmark.findtext(f'{{{XCCDF}}}title', ''), 'language': 'en'}],
        'description': [{'text': benchmark.findtext(f'{{{XCCDF}}}description', ''), 'language': 'en'}],
        'language': benchmark.get('{http://www.w3.org/XML/1998/namespace}lang'),
        'status': [{'value': child.text, **child.attrib} for child in benchmark.findall(f'{{{XCCDF}}}status')],
        'metadata': {'prototype_subset': True, 'omitted_rule_count': len(source.rules) - len(rule_ids)},
        'notices': [], 'front_matter': [], 'rear_matter': [], 'references': [], 'text_blocks': [],
        'platform': {'id': 'fixture-platform', 'title': 'Compilation fixture; applicability not converted', 'applicability': {}},
        'applicability_catalog': 'fixture-applicability', 'scoring': [], 'parameters': [], 'default_selection': True,
        'groups': [], 'profiles': profiles, 'rules': list(rule_links.values())}
    parameters={}
    for binding in rule_trace:
        for key,value in binding.get('policy_parameters',{}).items():
            ensure(key not in parameters or parameters[key]==value,'conflicting publisher Parameter binding')
            parameters[key]=value
    if parameters:
        wrapper['parameters']=[parameters[key] for key in sorted(parameters)]
    if rule_ids:
        documents['authoring/direct-slice/benchmark.json'] = {'benchmark': wrapper}
        documents['authoring/direct-slice/applicability.json'] = {'applicability': {'id': 'fixture-applicability', 'conditions': {}}}
    trace = {'format': 'direct-converter-spike/1', 'source_zip_sha256': source.zip_sha256, 'source_xml_sha256': source.xml_sha256,
        'source_member': source.member, 'source_benchmark_component': source.benchmark_component,
        'component_hashes': source.component_hashes, 'rules': rule_trace, 'profiles': profile_trace,
        'source_benchmark_metadata': [xml_identity(child) for child in benchmark if local_name(child) not in ('Group', 'Rule', 'Profile', 'Value')],
        'omitted_rules': sorted(set(source.rules) - set(rule_ids)), 'xml_parse_calls': source.parse_count,
        'component_index_passes': len(source.components), 'mapping_sha256': {m['capability']: digest(m) for m in mappings},
        'scope': 'Automated Assessment/selection subset, not full Rule-policy or Benchmark conversion',
        'unsupported': ['other Rules', 'manual execution', 'CPE/platform execution', 'full Rule metadata/remediation/scoring',
                        'other Object behaviors/traversal',
                        'record-level Variables, nested records, record absence and masking',
                        'all_exist', 'other capabilities/functions'],
        'coverage_promoted': False, 'scanner_evaluated': False}
    return documents, trace


def blocker_category(message):
    if 'unresolved' in message or 'cyclic' in message or 'wrong reference kind' in message:
        return 'source-invalid'
    if 'capability' in message:
        return 'unsupported-capability'
    if any(word in message for word in ('check selector', 'OVAL check', 'Profile', 'source default', 'non-OVAL', 'complex-check')):
        return 'unsupported-selection'
    return 'unsupported-construct'


def convert_benchmark(source, *, inventory_only=False, timings=None, mappings=None,
                      human_compact=True, validate_document=None):
    """Inventory all Rules; isolate expected per-Rule failures and validate admission.

    Native output is atomic per Rule. Diagnostic probes of blocked closures are
    cached per source node; they never produce content or change admission.
    Unexpected programming exceptions and global integrity faults propagate.
    """
    from v04_direct_inventory import SourceInventory, issue, summarize
    started = time.perf_counter()
    mappings = load_mappings() if mappings is None else mappings
    inventory = SourceInventory(source, mappings=mappings)
    rows = inventory.rules()
    inventory_counts = inventory.counts(rows)
    measured = {'inventory': time.perf_counter() - started, 'conversion': 0.0,
                'validation': 0.0, 'diagnostics': 0.0}
    documents, bindings, probes, accepted_parameters = {}, [], {}, {}
    if not inventory_only:
        if validate_document is None:
            from validate_native_json_schemas import build_validators, document_errors
            validators = build_validators(ROOT / 'schema/v0.4.0')
            validate_document = lambda kind, doc: document_errors(validators[kind + '.schema.json'], doc)
        for row in rows:
            blockers = list(row['inventory_problems'])
            native, binding = {}, None
            started = time.perf_counter()
            try:
                rule = source.rules[row['source_rule']]
                ensure(source.rule_selected(rule), 'disabled source defaults unsupported')
                native, binding = convert_rule(source, row['source_rule'], mappings,
                                               human_compact=human_compact)
                for key, parameter in binding.get('policy_parameters', {}).items():
                    ensure(key not in accepted_parameters or accepted_parameters[key] == parameter,
                           'conflicting Benchmark Parameter binding: '+key)
            except (UnsupportedSource, ValueError) as error:
                blockers.append(issue(blocker_category(str(error)), str(error), row['source_rule']))
            measured['conversion'] += time.perf_counter() - started
            started = time.perf_counter()
            if binding is not None:
                if set(native) & set(documents):
                    blockers.append(issue('native-identity',
                        'native Rule/Assessment name collision in selected source Rules', row['source_rule']))
                for path, document in native.items():
                    kind, = document
                    for error in validate_document(kind, document):
                        blockers.append(issue('schema-semantic', f'{path}: {error.message}', row['source_rule']))
            measured['validation'] += time.perf_counter() - started
            started = time.perf_counter()
            if blockers:
                # Probe every dependency, including those beyond the first failed
                # branch. Retain exact node IDs; never swallow unexpected errors.
                for node in row['dependencies']:
                    key = node['component'], node['id']
                    if key not in probes:
                        probes[key] = dependency_blockers(source, node, mappings)
                    blockers.extend(probes[key])
                # Distinct source contexts are kept even when diagnostics repeat.
                row['blockers'] = list({digest(b): b for b in blockers}.values())
                row['primary_blocker'] = row['blockers'][0]
                row['status'] = 'blocked'
            else:
                documents.update(native)
                accepted_parameters.update(binding.get('policy_parameters', {}))
                bindings.append(binding)
                row.update(status='converted', proof_level='authoring_validated', artifacts=sorted(native),
                           conversion_status='CONVERTED_UNVERIFIED')
                if binding.get('conversion_warnings'):
                    row['conversion_warnings'] = binding['conversion_warnings']
                    row['independent_static_proof_eligible'] = False
            measured['diagnostics'] += time.perf_counter() - started
    started = time.perf_counter()
    documents, trace = assemble_subset(source, documents, bindings, mappings)
    manifest = {'format': 'direct-benchmark-coverage/1', 'source_zip_sha256': source.zip_sha256,
        'source_xml_sha256': source.xml_sha256, 'source_member': source.member,
        'source_benchmark_component': source.benchmark_component,
        'component_hashes': source.component_hashes, 'mode': 'inventory' if inventory_only else 'automatic',
        'scope': 'Automated subset only; not complete Benchmark, manual, applicability or policy equivalence',
        'proof_contract': 'Conversion emits authoring_validated only. Compilation and independent source proof are separate gates.',
        'blocker_contract': 'All reference/selection inventory problems, conversion/schema diagnostics, dependency-node failures and independent supported entity/function/filter/quantifier obligations. Unsupported capability internals are not interpreted; further blockers may become discoverable only after implementation.',
        'inventory': inventory_counts, 'summary': summarize(rows), 'rules': rows,
        'coverage_promoted': False, 'scanner_evaluated': False}
    measured['assembly'] = time.perf_counter() - started
    if timings is not None:
        timings.update(measured)
    return documents, trace, manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--sha256', required=True)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--rule', action='append', help='strict focused selection; repeatable')
    selection.add_argument('--all-rules', action='store_true', help='inventory all, convert supported closures automatically')
    selection.add_argument('--inventory-only', action='store_true', help='discover every Rule without conversion')
    parser.add_argument('--verify', action='store_true',
                        help='validate original closures, prove source terms and compile only the proved primary subset')
    parser.add_argument('--draft', action='store_true',
                        help='allow warning-admitted catalog/all_exist drafts; never independent verification')
    parser.add_argument('--human-compact', action=argparse.BooleanOptionalAction, default=True,
                        help='source-aware scalar State compaction with inverse ledger; --verify still requires independent proof')
    parser.add_argument('--compile', action='store_true',
                        help='compile generated authoring and independently check package structure/operands; no semantic-proof claim')
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    ensure(not arguments.output.exists(), 'output exists; refusing overwrite')
    ensure(not (arguments.verify and arguments.inventory_only), '--verify requires --rule or --all-rules')
    ensure(not (arguments.verify and arguments.draft), '--draft and --verify are separate admission modes')
    ensure(not (arguments.compile and arguments.inventory_only), '--compile requires conversion')
    started = time.perf_counter()
    if arguments.verify:
        from verify_v04_direct_scope import accept_source
        report = accept_source(arguments.source, arguments.sha256, arguments.output, rule_ids=arguments.rule)
        metrics = {'verified_upgrade_seconds': time.perf_counter() - started, 'outcomes': report['outcomes']}
        (arguments.output / 'metrics.json').write_text(json.dumps(metrics, indent=2) + '\n')
        print(json.dumps(metrics))
        return
    source = SourceModel(arguments.source, arguments.sha256, inventory_broken_references=not bool(arguments.rule),
                         draft_compatibility=arguments.draft)
    indexed = time.perf_counter()
    manifest = None
    stages = {}
    if arguments.rule:
        documents, trace = convert(source, arguments.rule, human_compact=arguments.human_compact)
    else:
        documents, trace, manifest = convert_benchmark(source, inventory_only=arguments.inventory_only,
                                                       timings=stages, human_compact=arguments.human_compact)
    converted = time.perf_counter()
    from v04_direct_yaml import authoring_yaml
    arguments.output.mkdir(parents=True)
    for relative, document in documents.items():
        target = arguments.output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(document, indent=2) + '\n')
        target.with_suffix('.yaml').write_text(authoring_yaml(document))
    (arguments.output / 'source-trace.json').write_text(json.dumps(trace, indent=2) + '\n')
    if manifest is not None:
        from v04_direct_inventory import coverage_markdown
        (arguments.output / 'coverage.json').write_text(json.dumps(manifest, indent=2) + '\n')
        (arguments.output / 'coverage.md').write_text(coverage_markdown(manifest))
    if arguments.compile and documents:
        from v04_native_bundle_compiler import build_bundle
        from verify_v04_package_consumer import verify
        raw, _ = build_bundle(documents)
        package = arguments.output / 'CONVERTED_UNVERIFIED.scapng'
        package.write_bytes(raw)
        external = {(kind, doc[kind]['id']): (path, doc)
                    for path, doc in documents.items() for kind in doc}
        checked = verify(package, source=external)
        checked.update(independent_static_proof='NOT_ESTABLISHED_BY_COMPILATION', conversion_status='CONVERTED_UNVERIFIED')
        (arguments.output / 'package-verification.json').write_text(json.dumps(checked, indent=2)+'\n')
    metrics = {'parse_index': indexed - started, 'conversion': converted - indexed}
    if stages:
        metrics['stages'] = stages
    try:
        import resource
        metrics['process_peak_rss_kib_linux'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except ImportError:
        metrics['process_peak_rss_kib_linux'] = None
    (arguments.output / 'metrics.json').write_text(json.dumps(metrics, indent=2) + '\n')
    print(json.dumps(metrics))


if __name__ == '__main__':
    try:
        main()
    except (UnsupportedSource, zipfile.BadZipFile, OSError) as error:
        raise SystemExit(str(error))
