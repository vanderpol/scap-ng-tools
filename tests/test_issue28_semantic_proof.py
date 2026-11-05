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
