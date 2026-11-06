"""Independent source-semantic vectors; these do not exercise converter code."""
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / 'tools'))
from issue28_semantics import (Outcome, arithmetic, arithmetic_components, concat, concat_components,
                               count, flatten_components, quantify, regex_capture, split, substring,
                               unique, merge, EXISTENCE)


class OVALReferenceVectors(unittest.TestCase):
    def test_count_and_multi_component_aggregation_preserve_source_population(self):
        self.assertEqual(count([]), 0)
        self.assertEqual(count(['', 'a']), 2)
        self.assertEqual(count(flatten_components([['a', ''], ['a', 'b']])), 4)
        self.assertEqual(unique(flatten_components([['a', ''], ['a', 'b']])), ['a', '', 'b'])
        self.assertEqual(merge(flatten_components([['10'], ['2', '']]), ',', sort='document'),
                         '10,2,')

    def test_count_propagates_diagnostic_population_states(self):
        self.assertEqual(count([Outcome.ERROR]), Outcome.ERROR)
        self.assertEqual(count([Outcome.UNKNOWN]), Outcome.UNKNOWN)
        self.assertEqual(count([Outcome.NOT_EVALUATED]), Outcome.NOT_EVALUATED)

    def test_function_vectors_include_empty_and_nested_values(self):
        self.assertEqual(split('', ','), [''])
        self.assertEqual(split('a,,b', ','), ['a', '', 'b'])
        self.assertEqual(substring('abcdef', 1, 3), 'abc')
        self.assertEqual(substring('abcdef', 0, 0), '')
        self.assertEqual(concat(['', 'a', '']), 'a')
        self.assertEqual(regex_capture('id=42', r'id=(\d+)'), ['42'])
        self.assertEqual(regex_capture('no match', r'id=(\d+)'), [''])
        self.assertEqual(unique(['b', 'a', 'b', '']), ['b', 'a', ''])
        self.assertEqual(merge(['10', '2'], ',', sort='numeric'), '2,10')
        self.assertEqual(arithmetic([1, 2, 3], 'add'), 6)
        self.assertEqual(arithmetic([2, 3, 4], 'multiply'), 24)

    def test_oval_cartesian_and_boundary_vectors(self):
        self.assertEqual(arithmetic_components([[1, 2], [10, 20]], 'add'), [11, 21, 12, 22])
        self.assertEqual(concat_components([['a', 'b'], ['1', '2']]),
                         ['a1', 'a2', 'b1', 'b2'])
        self.assertEqual(split('', ''), [''])
        self.assertEqual(substring('abcdef', 0, 2), 'ab')
        self.assertEqual(substring('abcdef', 3, -1), 'cdef')
        self.assertEqual(substring('abcdef', 99, 1), Outcome.ERROR)
        self.assertEqual(merge(['b', 'a'], ',', sort='document', order='descending'), 'b,a')
        self.assertEqual(merge(['10', '2'], ',', sort='numeric', order='descending'), '10,2')

    def test_cardinality_and_error_propagation_vectors(self):
        self.assertEqual(quantify([], 'one_or_more'), Outcome.FALSE)
        self.assertEqual(quantify([True, True], 'every'), Outcome.TRUE)
        self.assertEqual(quantify([True, False], 'every'), Outcome.FALSE)
        self.assertEqual(quantify([Outcome.ERROR], 'one_or_more'), Outcome.ERROR)
        self.assertEqual(quantify([Outcome.UNKNOWN], 'none'), Outcome.UNKNOWN)
        self.assertEqual(quantify([], 'none'), Outcome.TRUE)

    def test_owner_existence_lowering_is_explicit_not_inferred(self):
        self.assertEqual(EXISTENCE['all_exist'], 'one_or_more')
        self.assertEqual(EXISTENCE['at_least_one_exists'], 'one_or_more')
        self.assertNotEqual(EXISTENCE['all_exist'], 'every')


if __name__ == '__main__':
    unittest.main()

class SelectionPolicyVectors(unittest.TestCase):
    def test_oval_default_is_selected_and_ocil_is_omitted_alternative(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter._v04_runtime.v04_direct_scap_source import SourceModel, OVAL, OCIL, XCCDF
        source = SourceModel.__new__(SourceModel)
        source.catalog = {'oval': 'oval-component'}
        source.draft_compatibility = False
        source.native_recovery = False
        rule = ET.fromstring(f'''<Rule xmlns="{XCCDF}" id="r">
          <check system="{OCIL}" selector="manual"><check-content-ref href="ocil" name="q"/></check>
          <check system="{OVAL}" selector=""><check-content-ref href="oval" name="d"/></check>
        </Rule>''')
        component, definition, omitted = source.automated_check(rule)
        self.assertEqual((component, definition), ('oval-component', 'd'))
        self.assertEqual(omitted[0]['system'], OCIL)
        self.assertIn('source', omitted[0])

class RecoveryFunctionBoundary(unittest.TestCase):
    def test_native_recovery_requires_exact_function_options(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_converter import AssessmentConverter
        from v04_direct_scap_source import OVAL
        visitor = AssessmentConverter(None, None, [], native_recovery=True)
        source = ET.fromstring(
            f'<split xmlns="{OVAL}" delimiter=","><literal_component datatype="string">a,b</literal_component></split>')
        expression = visitor.function(source)
        self.assertEqual(expression['function']['name'], 'split')
        self.assertEqual(expression['function']['options'], {'delimiter': ','})
        bad = ET.fromstring(
            f'<substring xmlns="{OVAL}" substring_start="1.0" substring_length="1"><literal_component datatype="string">x</literal_component></substring>')
        with self.assertRaisesRegex(ValueError, 'xsd:int'):
            visitor.function(bad)

class NativeFunctionContractSemantics(unittest.TestCase):
    class _NoSchemaErrors:
        @staticmethod
        def iter_errors(_declaration):
            return iter(())

    @staticmethod
    def _literal(datatype, value):
        return {'literal': {'datatype': datatype, 'value': value}}

    def _validate(self, declaration):
        from scap_ng_tools.converter._v04_semantic.v04_variable_expressions import (
            assessment_variable_expressions)
        assessment = {'variables': {'result-variable': declaration}}
        with patch('scap_ng_tools.converter._v04_semantic.v04_variable_expressions.declaration_validator',
                   return_value=self._NoSchemaErrors()):
            return assessment_variable_expressions(assessment)

    def test_owner_function_subset_preserves_numeric_widening_and_string_results(self):
        arithmetic = {'function': {'name': 'arithmetic', 'arguments': [
            self._literal('integer', 2), self._literal('float', 1.5)],
            'options': {'arithmetic_operation': 'multiply'}}}
        self.assertEqual(self._validate({'kind': 'local', 'datatype': 'float',
                                         'expression': arithmetic})['result-variable'], 'float')
        split = {'function': {'name': 'split', 'arguments': [self._literal('string', 'a,,b')],
                              'options': {'delimiter': ','}}}
        self.assertEqual(self._validate({'kind': 'local', 'datatype': 'string',
                                         'expression': split})['result-variable'], 'string')
        substring = {'function': {'name': 'substring', 'arguments': [self._literal('string', 'abc')],
                                  'options': {'substring_start': 1, 'substring_length': 2}}}
        self.assertEqual(self._validate({'kind': 'local', 'datatype': 'string',
                                         'expression': substring})['result-variable'], 'string')

    def test_recovered_function_contract_accepts_count_and_multi_component_aggregation(self):
        count = {'function': {'name': 'count', 'arguments': [
            self._literal('string', ['a', 'b']),
            self._literal('integer', [1, 2])], 'options': {}}}
        self.assertEqual(self._validate({'kind': 'local', 'datatype': 'integer',
                                         'expression': count})['result-variable'], 'integer')
        unique = {'function': {'name': 'unique', 'arguments': [
            self._literal('string', ['a', 'b']), self._literal('string', ['b', 'c'])],
            'options': {}}}
        self.assertEqual(self._validate({'kind': 'local', 'datatype': 'string',
                                         'expression': unique})['result-variable'], 'string')
        merge = {'function': {'name': 'merge', 'arguments': [
            self._literal('integer', [10, 2]), self._literal('string', [''])],
            'options': {'delimiter': ',', 'sort': 'numeric', 'order': 'ascending'}}}
        self.assertEqual(self._validate({'kind': 'local', 'datatype': 'string',
                                         'expression': merge})['result-variable'], 'string')

    def test_recovered_function_contract_rejects_bad_domains_and_arity(self):
        empty_concat = {'function': {'name': 'concat', 'arguments': [
            self._literal('string', [])], 'options': {}}}
        with self.assertRaisesRegex(ValueError, 'at least two'):
            self._validate({'kind': 'local', 'datatype': 'string', 'expression': empty_concat})
        bad_unique = {'function': {'name': 'unique', 'arguments': [
            self._literal('record', {'id': 1})], 'options': {}}}
        with self.assertRaisesRegex(ValueError, 'scalar text operand'):
            self._validate({'kind': 'local', 'datatype': 'string', 'expression': bad_unique})
        bad_count = {'function': {'name': 'count', 'arguments': [], 'options': {}}}
        with self.assertRaisesRegex(ValueError, 'one or more'):
            self._validate({'kind': 'local', 'datatype': 'integer', 'expression': bad_count})

    def test_owner_function_subset_rejects_implicit_casts_and_bad_options(self):
        numeric_split = {'function': {'name': 'split', 'arguments': [self._literal('integer', 2)],
                                      'options': {'delimiter': ','}}}
        self.assertEqual(self._validate({'kind': 'local', 'datatype': 'string',
                                         'expression': numeric_split})['result-variable'], 'string')
        bad_substring = {'function': {'name': 'substring', 'arguments': [self._literal('string', 'abc')],
                                      'options': {'substring_start': 1.0, 'substring_length': 2}}}
        with self.assertRaisesRegex(ValueError, 'signed 32-bit'):
            self._validate({'kind': 'local', 'datatype': 'string', 'expression': bad_substring})


class AbsencePrecedence(unittest.TestCase):
    def test_existence_none_drops_comparator_with_warning(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_converter import AssessmentConverter
        from v04_direct_scap_source import OVAL
        visitor = AssessmentConverter(None, None, [])
        element = ET.fromstring(
            f'<stderr_line xmlns="{OVAL}" check_existence="none_exist" operation="pattern match">.*</stderr_line>')
        result = visitor.predicate(element, {})
        self.assertEqual(result, {'values_found': 'none'})
        self.assertEqual(visitor.conversion_warnings[0]['code'],
                         'oval_absence_comparator_ignored')

class IdentityCollisionRecovery(unittest.TestCase):
    def test_identical_source_descriptors_get_source_discriminators(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_converter import AssessmentConverter
        from v04_direct_scap_source import OVAL
        first = ET.fromstring(f'<registry_test xmlns="{OVAL}#windows" id="oval:a:tst:1" comment="Same"><object object_ref="oval:a:o:1"/></registry_test>')
        second = ET.fromstring(f'<registry_test xmlns="{OVAL}#windows" id="oval:a:tst:2" comment="Same"><object object_ref="oval:a:o:2"/></registry_test>')
        source = type('Source', (), {'nodes': {'component': {
            n.get('id'): n for n in (first, second)
        }}})()
        visitor = AssessmentConverter(source, 'component', [], native_recovery=True)
        a = visitor.native_name(first, 'test')
        b = visitor.native_name(second, 'test')
        self.assertNotEqual(a, b)
        self.assertLessEqual(len(a), 64)
        self.assertLessEqual(len(b), 64)

class NilSelectorRecovery(unittest.TestCase):
    def test_registry_key_and_name_nil_selectors_are_native_null(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_converter import AssessmentConverter
        from v04_direct_scap_source import OVAL
        mapping = {'capability': 'windows.registry', 'native': {
            'selector_map': {'key': 'key', 'name': 'name'},
            'nullable_selectors': ('key', 'name'),
            'field_datatypes': {'key': ['string'], 'name': ['string']},
        }}
        visitor = AssessmentConverter(None, None, [])
        for field in ('key', 'name'):
            element = ET.fromstring(
                f'<{field} xmlns="{OVAL}#windows" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true"/>')
            with self.subTest(field=field):
                self.assertIsNone(visitor.predicate(element, mapping, selector=True))

    def test_registry_nil_selector_rejects_comparator_and_text(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_converter import AssessmentConverter
        from v04_direct_scap_source import OVAL
        mapping = {'capability': 'windows.registry', 'native': {
            'selector_map': {'key': 'key'}, 'nullable_selectors': ('key',),
            'field_datatypes': {'key': ['string']},
        }}
        visitor = AssessmentConverter(None, None, [])
        bad = ET.fromstring(
            f'<key xmlns="{OVAL}#windows" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true" operation="pattern match"/>')
        with self.assertRaisesRegex(ValueError, 'unsupported attributes'):
            visitor.predicate(bad, mapping, selector=True)
        bad_text = ET.fromstring(
            f'<key xmlns="{OVAL}#windows" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true">x</key>')
        with self.assertRaisesRegex(ValueError, 'unsupported nil selector'):
            visitor.predicate(bad_text, mapping, selector=True)

    def test_record_cmdlet_nil_without_datatype_is_native_null(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_cmdlet_inputs import cmdlet_input
        element = ET.fromstring('<parameters xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true"/>')
        self.assertIsNone(cmdlet_input(element, {'schema_ref': 'object_record', 'nullable': True},
                                       lambda _: {}, lambda _: None, native_recovery=True))

    def test_record_cmdlet_nil_rejects_wrong_explicit_datatype(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_cmdlet_inputs import cmdlet_input
        element = ET.fromstring('<parameters xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true" datatype="string"/>')
        with self.assertRaisesRegex(ValueError, 'invalid nil input datatype'):
            cmdlet_input(element, {'schema_ref': 'object_record', 'nullable': True},
                         lambda _: {}, lambda _: None, native_recovery=True)

class RecursionRecovery(unittest.TestCase):
    def test_typed_equality_path_allows_downward_traversal(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_file_behaviors import traversal_behaviors
        behaviors = ET.fromstring('<behaviors max_depth="2" recurse_direction="down"/>')
        acquisition = {'directory': {'case_insensitive_equals': {'variable': 'root-variable'}}}
        result = traversal_behaviors(behaviors, acquisition, windows=True, native_recovery=True)
        self.assertEqual(result['traversal'], {'max_depth': 2, 'recurse': 'directories'})

    def test_pattern_path_recovery_drops_invalid_recursion_and_logs(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_file_behaviors import traversal_behaviors
        behaviors = ET.fromstring('<behaviors max_depth="2" recurse="junctions" recurse_direction="down"/>')
        acquisition = {'directory': {'matches_regex': '^Windows$'}}
        warnings = []
        result = traversal_behaviors(behaviors, acquisition, windows=True,
                                     native_recovery=True, warnings=warnings)
        self.assertEqual(result, {'filesystem': 'all'})
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0]['code'], 'oval_invalid_path_recursion_removed')
        self.assertEqual(warnings[0]['path_kind'], 'pattern_path')
        self.assertEqual(set(warnings[0]['removed_attributes']),
                         {'max_depth', 'recurse', 'recurse_direction'})

    def test_pattern_path_still_rejects_recursion_in_historical_mode(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_file_behaviors import traversal_behaviors
        behaviors = ET.fromstring('<behaviors max_depth="2" recurse_direction="down"/>')
        acquisition = {'directory': {'matches_regex': '^Windows$'}}
        with self.assertRaisesRegex(ValueError, 'pattern-path recursion'):
            traversal_behaviors(behaviors, acquisition, windows=True)

    def test_full_path_recovery_drops_invalid_recursion_and_preserves_filesystem(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_file_behaviors import traversal_behaviors
        behaviors = ET.fromstring('<behaviors max_depth="bogus" recurse_direction="down" recurse_file_system="local"/>')
        acquisition = {'full_path': {'equals': 'C:\\Windows\\System32\\x.dll'}}
        warnings = []
        result = traversal_behaviors(behaviors, acquisition, windows=True,
                                     native_recovery=True, warnings=warnings)
        self.assertEqual(result, {'filesystem': 'local'})
        self.assertEqual(warnings[0]['path_kind'], 'full_path')
        self.assertEqual(set(warnings[0]['removed_attributes']),
                         {'max_depth', 'recurse_direction'})

    def test_typed_case_insensitive_hierarchy_key_allows_downward_traversal(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_file_behaviors import hierarchy_behaviors
        behaviors = ET.fromstring('<behaviors max_depth="2" recurse_direction="down"/>')
        acquisition = {'key': {'case_insensitive_equals': 'HKLM\\Software'}}
        result = hierarchy_behaviors(behaviors, acquisition, native_recovery=True)
        self.assertEqual(result, {'traversal': {'max_depth': 2}})

    def test_historical_hierarchy_path_keeps_case_sensitive_boundary(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_file_behaviors import hierarchy_behaviors
        behaviors = ET.fromstring('<behaviors max_depth="2" recurse_direction="down"/>')
        acquisition = {'key': {'case_insensitive_equals': 'HKLM\\Software'}}
        with self.assertRaisesRegex(ValueError, 'equality key'):
            hierarchy_behaviors(behaviors, acquisition)

class CountRecovery(unittest.TestCase):
    def test_count_uses_the_canonical_function_call_envelope(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_converter import AssessmentConverter
        from v04_direct_scap_source import OVAL
        visitor = AssessmentConverter(None, None, [], native_recovery=True)
        source = ET.fromstring(f'<count xmlns="{OVAL}"><literal_component datatype="string">a</literal_component></count>')
        expression = visitor.function(source)
        self.assertEqual(expression['function']['name'], 'count')
        self.assertEqual(expression['function']['options'], {})
        self.assertEqual(len(expression['function']['arguments']), 1)

    def test_count_requires_at_least_one_operand(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_converter import AssessmentConverter
        from v04_direct_scap_source import OVAL
        visitor = AssessmentConverter(None, None, [], native_recovery=True)
        source = ET.fromstring(f'<count xmlns="{OVAL}"/>')
        with self.assertRaisesRegex(ValueError, 'function arity mismatch'):
            visitor.function(source)

    def test_count_preserves_all_source_components(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_converter import AssessmentConverter
        from v04_direct_scap_source import OVAL
        visitor = AssessmentConverter(None, None, [], native_recovery=True)
        source = ET.fromstring(f'''<count xmlns="{OVAL}">
          <literal_component datatype="string">a</literal_component>
          <literal_component datatype="string">b</literal_component>
        </count>''')
        expression = visitor.function(source)
        self.assertEqual(expression['function']['name'], 'count')
        self.assertEqual(len(expression['function']['arguments']), 2)
        self.assertEqual([a['literal']['value'] for a in expression['function']['arguments']], ['a', 'b'])

class MultiComponentAggregationRecovery(unittest.TestCase):
    def test_unique_preserves_ordered_components_in_recovery_envelope(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_converter import AssessmentConverter
        from v04_direct_scap_source import OVAL
        visitor = AssessmentConverter(None, None, [], native_recovery=True)
        source = ET.fromstring(f'''<unique xmlns="{OVAL}">
          <literal_component datatype="string">a</literal_component>
          <literal_component datatype="string">b</literal_component>
        </unique>''')
        expression = visitor.function(source)
        self.assertEqual(expression['function']['name'], 'unique')
        self.assertEqual(len(expression['function']['arguments']), 2)
        self.assertEqual(expression['function']['options'], {})
        self.assertEqual(visitor.conversion_warnings[-1]['source_component_count'], 2)

    def test_merge_preserves_options_and_components_in_recovery_envelope(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_converter import AssessmentConverter
        from v04_direct_scap_source import OVAL
        visitor = AssessmentConverter(None, None, [], native_recovery=True)
        source = ET.fromstring(f'''<merge xmlns="{OVAL}" delimiter="," sort="numeric" order="descending">
          <literal_component datatype="string">10</literal_component>
          <literal_component datatype="string">2</literal_component>
        </merge>''')
        expression = visitor.function(source)
        self.assertEqual(expression['function']['name'], 'merge')
        self.assertEqual(len(expression['function']['arguments']), 2)
        self.assertEqual(expression['function']['options'], {
            'delimiter': ',', 'sort': 'numeric', 'order': 'descending'})

    def test_default_path_still_rejects_multi_component_aggregation(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_converter import AssessmentConverter
        from v04_direct_scap_source import OVAL
        visitor = AssessmentConverter(None, None, [])
        source = ET.fromstring(f'''<unique xmlns="{OVAL}">
          <literal_component datatype="string">a</literal_component>
          <literal_component datatype="string">b</literal_component>
        </unique>''')
        with self.assertRaisesRegex(ValueError, 'multiple aggregation components'):
            visitor.function(source)

class NestedCountRecovery(unittest.TestCase):
    def test_nested_legacy_function_is_migrated_inside_count(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_converter import AssessmentConverter
        from v04_direct_scap_source import OVAL
        visitor = AssessmentConverter(None, None, [], native_recovery=True)
        source = ET.fromstring(f'''<count xmlns="{OVAL}">
          <unique><literal_component datatype="string">a</literal_component></unique>
        </count>''')
        expression = visitor.function(source)
        self.assertEqual(expression['function']['arguments'][0]['function']['name'], 'unique')

class XccdfValueMetadataRecovery(unittest.TestCase):
    def test_non_executable_value_warning_is_accepted_as_provenance_metadata(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_scap_source import attributes, XCCDF
        value = ET.fromstring(f'''<Value xmlns="{XCCDF}" id="v" type="number">
          <warning category="general">Informational guidance</warning>
          <value>1</value>
        </Value>''')
        warnings = value.findall(f'{{{XCCDF}}}warning')
        self.assertEqual(len(warnings), 1)
        attributes(warnings[0], {'category', '{http://www.w3.org/XML/1998/namespace}lang'})

class ParameterIdentityRecovery(unittest.TestCase):
    def test_distinct_value_ids_disambiguate_identical_parameter_descriptors(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_draft_inputs import value_parameter_identifier
        from v04_direct_scap_source import XCCDF
        first = ET.fromstring(f'<Value xmlns="{XCCDF}" id="v-one"><title>Same parameter</title></Value>')
        second = ET.fromstring(f'<Value xmlns="{XCCDF}" id="v-two"><title>Same parameter</title></Value>')
        source = type('Source', (), {'nodes': {'benchmark': {'v-one': first, 'v-two': second}},
                                     'benchmark_component': 'benchmark'})()
        visitor = type('Visitor', (), {'source': source})()
        a = value_parameter_identifier(visitor, first)
        b = value_parameter_identifier(visitor, second)
        self.assertNotEqual(a, b)
        self.assertLessEqual(len(a), 64)
        self.assertLessEqual(len(b), 64)

class TypedAcquisitionParameterRecovery(unittest.TestCase):
    def test_version_typed_cmdlet_parameter_keeps_version_lexical_domain(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_converter import AssessmentConverter
        element = ET.fromstring('<module_version datatype="version">1.0.0.0</module_version>')
        self.assertEqual(AssessmentConverter(None, None, []).parameter(element, datatype='version'), '1.0.0.0')

class RemainingFunctionRecovery(unittest.TestCase):
    def test_end_uses_explicit_character_and_canonical_nested_operand(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_converter import AssessmentConverter
        from v04_direct_scap_source import OVAL
        visitor = AssessmentConverter(None, None, [], native_recovery=True)
        source = ET.fromstring(f'''<end xmlns="{OVAL}" character="\\">
          <unique><literal_component datatype="string">a</literal_component></unique>
        </end>''')
        expression = visitor.function(source)
        self.assertEqual(expression['function']['name'], 'end')
        self.assertEqual(expression['function']['options'], {'character': '\\'})
        self.assertEqual(expression['function']['arguments'][0]['function']['name'], 'unique')

    def test_existing_canonical_nested_expression_is_rejected_by_default_migration(self):
        import sys
        sys.path.insert(0, str(__import__('pathlib').Path(__file__).parents[1] / 'src/scap_ng_tools/converter/_v04_runtime'))
        from v04_variable_function_migration import canonical_expression, UnsupportedExpression
        with self.assertRaises(UnsupportedExpression):
            canonical_expression({'function': {'name': 'unique', 'arguments': [], 'options': {}}})
