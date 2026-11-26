"""Exact binary32 conversion boundaries for the canonical float contract."""
import os
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

from scap_ng_tools.converter.direct04 import convert_benchmark, convert_focused, load_runtime


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
            for recovery in (False, True):
                with self.subTest(operation=operation, recovery=recovery):
                    visitor = AssessmentConverter(None, None, [], native_recovery=recovery)
                    element = ET.fromstring(
                        f'<subexpression xmlns="{OVAL}" datatype="float" '
                        f'operation="{operation}">9.9999999</subexpression>')
                    result = visitor.predicate(element, mapping)
                    self.assertEqual(result[native], 10.0)
                    self.assertEqual(visitor.conversion_warnings[0]['code'],
                                     'native_float_binary32_contract')

    def test_production_float_predicate_rejects_nonfinite_operands(self):
        mapping = {'capability': 'independent.shellcommand',
                   'native': {'state_field_map': {'subexpression': 'subexpression'},
                              'state_value_enums': {}}}
        element = ET.fromstring(
            f'<subexpression xmlns="{OVAL}" datatype="float" '
            'operation="greater than or equal">INF</subexpression>')
        with self.assertRaisesRegex(ValueError, 'float lexical form'):
            AssessmentConverter(None, None, []).predicate(element, mapping)

    @unittest.skipUnless(os.environ.get('SCAP_NG_UBUNTU_FIXTURES_ROOT')
                         and os.environ.get('SCAP_NG_SCHEMA_ROOT'), 'requires pinned Ubuntu and schema fixtures')
    def test_production_focused_and_bulk_preserve_ubuntu_float_rule(self):
        source = Path(os.environ['SCAP_NG_UBUNTU_FIXTURES_ROOT']) / (
            'U_CAN_Ubuntu_24-04_LTS_V1R6_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.zip')
        rule_id = 'xccdf_mil.disa.stig_rule_SV-270816r1066937_rule'
        options = dict(schema_root=Path(os.environ['SCAP_NG_SCHEMA_ROOT']),
                       source=source,
                       sha256_pin='9429eb85a8fd36f9b46360f1567a61c251a0a8016b5575d8e595536b41dbca42')
        focused_docs, focused_trace = convert_focused(**options, rule_ids=[rule_id])
        bulk_docs, bulk_trace, coverage = convert_benchmark(**options)
        self.assertEqual(coverage['summary']['source_rules'], 195)
        self.assertEqual(len(bulk_trace['rules']), 195)
        self.assertEqual(bulk_trace['omitted_rules'], [])
        row, = [row for row in coverage['rules'] if row['source_rule'] == rule_id]
        self.assertEqual(row['status'], 'converted')
        self.assertEqual(row['inventory_problems'], [])
        binding, = focused_trace['rules']
        self.assertEqual(binding, next(row for row in bulk_trace['rules'] if row['source_rule'] == rule_id))
        for path in row['artifacts']:
            self.assertEqual(focused_docs[path], bulk_docs[path])
        self.assertEqual(len(binding['manual_alternatives']), 1)
        warning, = [entry for entry in binding['conversion_warnings']
                    if entry['code'] == 'native_float_binary32_contract']
        self.assertEqual(warning['source_lexical'], '10.0')
        self.assertFalse(warning['scanner_evaluated'])


if __name__ == '__main__':
    unittest.main()
