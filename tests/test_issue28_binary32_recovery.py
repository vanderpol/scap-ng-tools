"""Exact binary32 conversion boundaries for Issue #28 float recovery."""
import struct
import unittest
import xml.etree.ElementTree as ET

from scap_ng_tools.converter.direct04 import load_runtime


load_runtime()
from v04_direct_converter import AssessmentConverter  # noqa: E402
from v04_direct_datatypes import binary32_bits, binary32_literal  # noqa: E402
from v04_direct_scap_source import OVAL  # noqa: E402


class Binary32Recovery(unittest.TestCase):
    def test_direct_decimal_rounding_uses_contract_vectors(self):
        vectors = {
            '10.0': '41200000',
            '9.9999999': '41200000',
            '1.000000059604644775390625': '3f800000',
            '1.0000000596046447753906250000000001': '3f800001',
            '1.40129846432481707092372958328991613128026194187651577175706828388979108268586060148663818836212158203125e-45': '00000001',
            '-1e-46': '80000000',
            '3.40282346638528859811704183484516925440e38': '7f7fffff',
        }
        for lexical, expected in vectors.items():
            with self.subTest(lexical=lexical):
                self.assertEqual(f'{binary32_bits(lexical):08x}', expected)

    def test_invalid_and_nonfinite_expected_values_fail_closed(self):
        for lexical in ('', 'NaN', 'INF', '-INF', '0x1.0p0', '１.０', '\u00a010.0', '1e999999'):
            with self.subTest(lexical=lexical):
                with self.assertRaises(ValueError):
                    binary32_literal(lexical)

    def test_all_six_float_comparators_are_self_describing(self):
        mapping = {'capability': 'independent.shellcommand',
                   'native': {'state_field_map': {'subexpression': 'subexpression'},
                              'state_value_enums': {}}}
        for operation, native in (
                ('equals', 'float_equals'), ('not equal', 'float_not_equal'),
                ('greater than', 'float_greater_than'),
                ('greater than or equal', 'float_greater_than_or_equal'),
                ('less than', 'float_less_than'),
                ('less than or equal', 'float_less_than_or_equal')):
            with self.subTest(operation=operation):
                visitor = AssessmentConverter(None, None, [], native_recovery=True)
                element = ET.fromstring(
                    f'<subexpression xmlns="{OVAL}" datatype="float" '
                    f'operation="{operation}">9.9999999</subexpression>')
                result = visitor.predicate(element, mapping)
                self.assertEqual(set(result) & {native}, {native})
                self.assertEqual(result[native], 10.0)
                self.assertEqual(visitor.conversion_warnings[0]['code'],
                                 'native_float_binary32_contract')

    def test_historical_path_does_not_silently_coerce_float(self):
        mapping = {'capability': 'independent.shellcommand',
                   'native': {'state_field_map': {'subexpression': 'subexpression'},
                              'state_value_enums': {}}}
        element = ET.fromstring(
            f'<subexpression xmlns="{OVAL}" datatype="float" '
            'operation="greater than or equal">10.0</subexpression>')
        with self.assertRaisesRegex(ValueError, 'binary32 recovery contract'):
            AssessmentConverter(None, None, []).predicate(element, mapping)


if __name__ == '__main__':
    unittest.main()
