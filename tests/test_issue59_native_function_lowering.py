"""SCAP-NG 0.4.1: recovered OVAL functions must use the active native grammar.

These are syntax/provenance witnesses, not executable OVAL or RI equivalence.
Multi-component count is deliberately blocked until a lossless mapping exists.
"""
import unittest
import xml.etree.ElementTree as ET

from scap_ng_tools.converter.direct04 import load_runtime

load_runtime()
from v04_direct_converter import AssessmentConverter  # noqa: E402
from v04_direct_scap_source import OVAL  # noqa: E402


def oval(source):
    return ET.fromstring(source.replace('xmlns="OVAL"', 'xmlns="' + OVAL + '"'))


class Active041FunctionLowering(unittest.TestCase):
    def visitor(self, *, recovery=True):
        return AssessmentConverter(None, None, [], native_recovery=recovery)

    def test_nested_count_unique_keeps_source_order_and_duplicate_boundary(self):
        visitor = self.visitor()
        source = oval(
            '<count xmlns="OVAL"><unique>'
            '<literal_component datatype="string">alpha</literal_component>'
            '<literal_component datatype="string">alpha</literal_component>'
            '<literal_component datatype="string">beta</literal_component>'
            '</unique></count>')
        value = visitor.function(source)
        self.assertEqual(value, {'count': {'unique': [
            {'literal': {'datatype': 'string', 'value': 'alpha'}},
            {'literal': {'datatype': 'string', 'value': 'alpha'}},
            {'literal': {'datatype': 'string', 'value': 'beta'}},
        ]}})
        self.assertNotIn('function', str(value))
        self.assertEqual(visitor.conversion_warnings[0]['independent_static_proof'], 'UNPROVED')
        self.assertFalse(visitor.conversion_warnings[0]['scanner_evaluated'])

    def test_native_arithmetic_preserves_order_and_numeric_literal_types(self):
        visitor = self.visitor()
        source = oval(
            '<arithmetic xmlns="OVAL" arithmetic_operation="multiply">'
            '<literal_component datatype="int">2</literal_component>'
            '<literal_component datatype="int">3</literal_component>'
            '</arithmetic>')
        self.assertEqual(visitor.function(source), {
            'arithmetic': {
                'arithmetic_operation': 'multiply',
                'values': [
                    {'literal': {'datatype': 'integer', 'value': 2}},
                    {'literal': {'datatype': 'integer', 'value': 3}},
                ],
            },
        })

    def test_unary_source_options_are_preserved_in_exact_native_form(self):
        cases = [
            ('<split delimiter=","><literal_component datatype="string">a,,b</literal_component></split>',
             'split', {'delimiter': ','}),
            ('<substring substring_start="-2" substring_length="3"><literal_component datatype="string">abcdef</literal_component></substring>',
             'substring', {'substring_start': -2, 'substring_length': 3}),
            ('<begin character="/"><literal_component datatype="string">/etc</literal_component></begin>',
             'begin', {'character': '/'}),
            ('<end character="/"><literal_component datatype="string">/etc</literal_component></end>',
             'end', {'character': '/'}),
        ]
        for fragment, operation, options in cases:
            with self.subTest(operation=operation):
                visitor = self.visitor()
                source = oval(fragment.replace('>', ' xmlns="OVAL">', 1))
                expression = visitor.function(source)
                self.assertEqual(set(expression), {operation})
                self.assertEqual(expression[operation], {
                    **options,
                    'value': expression[operation]['value'],
                })
                self.assertEqual(set(expression[operation]['value']), {'literal'})

    def test_multi_component_count_fails_closed_without_losing_multiplicity(self):
        visitor = self.visitor()
        source = oval(
            '<count xmlns="OVAL">'
            '<literal_component datatype="string">a</literal_component>'
            '<literal_component datatype="string">a</literal_component>'
            '</count>')
        with self.assertRaisesRegex(ValueError, 'multi-component OVAL count'):
            visitor.function(source)

    def test_unsupported_arithmetic_and_default_recovery_are_not_promoted(self):
        source = oval(
            '<arithmetic xmlns="OVAL" arithmetic_operation="divide">'
            '<literal_component datatype="int">6</literal_component>'
            '<literal_component datatype="int">3</literal_component>'
            '</arithmetic>')
        with self.assertRaisesRegex(ValueError, 'unsupported arithmetic operation'):
            self.visitor().function(source)
        source = oval(
            '<count xmlns="OVAL"><literal_component datatype="string">x</literal_component></count>')
        with self.assertRaisesRegex(ValueError, 'unsupported function: count'):
            self.visitor(recovery=False).function(source)


if __name__ == '__main__':
    unittest.main()
