"""Independent source-semantic vectors; these do not exercise converter code."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / 'tools'))
from issue28_semantics import (Outcome, arithmetic, concat, quantify, regex_capture,
                               split, substring, unique, merge, EXISTENCE)


class OVALReferenceVectors(unittest.TestCase):
    def test_function_vectors_include_empty_and_nested_values(self):
        self.assertEqual(split('', ','), [''])
        self.assertEqual(split('a,,b', ','), ['a', '', 'b'])
        self.assertEqual(substring('abcdef', 1, 3), 'bcd')
        self.assertEqual(substring('abcdef', 0, 0), '')
        self.assertEqual(concat(['', 'a', '']), 'a')
        self.assertEqual(regex_capture('id=42', r'id=(\d+)'), ['42'])
        self.assertEqual(regex_capture('no match', r'id=(\d+)'), [])
        self.assertEqual(unique(['b', 'a', 'b', '']), ['b', 'a', ''])
        self.assertEqual(merge(['10', '2'], ',', sort='numeric'), '2,10')
        self.assertEqual(arithmetic([1, 2, 3], 'add'), 6)
        self.assertEqual(arithmetic([2, 3, 4], 'multiply'), 24)

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
        visitor = AssessmentConverter(source, 'component', [])
        a = visitor.native_name(first, 'test')
        b = visitor.native_name(second, 'test')
        self.assertNotEqual(a, b)
        self.assertLessEqual(len(a), 64)
        self.assertLessEqual(len(b), 64)

class NilSelectorRecovery(unittest.TestCase):
    def test_record_cmdlet_nil_without_datatype_is_native_null(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_cmdlet_inputs import cmdlet_input
        element = ET.fromstring('<parameters xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true"/>')
        self.assertIsNone(cmdlet_input(element, {'schema_ref': 'object_record', 'nullable': True},
                                       lambda _: {}, lambda _: None))

    def test_record_cmdlet_nil_rejects_wrong_explicit_datatype(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_cmdlet_inputs import cmdlet_input
        element = ET.fromstring('<parameters xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true" datatype="string"/>')
        with self.assertRaisesRegex(ValueError, 'invalid nil input datatype'):
            cmdlet_input(element, {'schema_ref': 'object_record', 'nullable': True},
                         lambda _: {}, lambda _: None)

class RecursionRecovery(unittest.TestCase):
    def test_typed_equality_path_allows_downward_traversal(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_file_behaviors import traversal_behaviors
        behaviors = ET.fromstring('<behaviors max_depth="2" recurse_direction="down"/>')
        acquisition = {'directory': {'case_insensitive_equals': {'variable': 'root-variable'}}}
        result = traversal_behaviors(behaviors, acquisition, windows=True)
        self.assertEqual(result['traversal'], {'max_depth': 2, 'recurse': 'directories'})

    def test_pattern_path_still_rejects_recursion(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_file_behaviors import traversal_behaviors
        behaviors = ET.fromstring('<behaviors max_depth="2" recurse_direction="down"/>')
        acquisition = {'directory': {'matches_regex': '^Windows$'}}
        with self.assertRaisesRegex(ValueError, 'pattern-path recursion'):
            traversal_behaviors(behaviors, acquisition, windows=True)

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

    def test_count_requires_one_operand(self):
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_converter import AssessmentConverter
        from v04_direct_scap_source import OVAL
        visitor = AssessmentConverter(None, None, [], native_recovery=True)
        source = ET.fromstring(f'<count xmlns="{OVAL}"/>')
        with self.assertRaisesRegex(ValueError, 'function arity mismatch'):
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
