"""0.3 source function behavior ported into active 0.4.1 native authoring.

0.3 source: vanderpol/scap-ng-research/tools/oval_semantic_ir.py
at fc62031c7d8bea470e6bdbc6629bc1c96deb597a, blob
541f10bdfa315721cbd9b3216156b1a8d0eaf9af, lines 1245-1257,
1410-1447. These are narrow syntax and static source-behavior witnesses;
no RI/SCC execution or scanner equivalence is claimed.
"""
import unittest
from copy import deepcopy

from scap_ng_tools.converter.native041_function_lowering import lower_expression


def source_call(name, operand, **options):
    return {'function': {'name': name, 'arguments': [operand], 'options': options}}


class V003FunctionRestoration(unittest.TestCase):
    def test_split_collected_field_has_explicit_text_projection(self):
        source = source_call('split', {'values': {
            'object': {'capability': 'independent.textfilecontent', 'filepath': '/a'},
            'field': 'subexpression'}}, delimiter=',')
        original = deepcopy(source)
        result = lower_expression(source)
        self.assertEqual(source, original)
        self.assertEqual(result['split']['delimiter'], ',')
        self.assertEqual(result['split']['value'], {'concat': [
            {'literal': ''}, source['function']['arguments'][0]]})
        # 0.3 per-value str/split preserves adjacent/edge empties.
        self.assertEqual('a,,b,'.split(','), ['a', '', 'b', ''])
        self.assertEqual(''.split(','), [''])
        # Singleton empty prefix and arbitrary source cardinality preserve
        # value order/multiplicity; do not de-duplicate.
        for values in (['alpha,beta', '', 'alpha,beta'], ['a,,b', ',z,']):
            before_split = [part for value in values for part in value.split(',')]
            after_project = [part for value in ['' + v for v in values]
                             for part in value.split(',')]
            self.assertEqual(after_project, before_split)

    def test_substring_collected_field_port_keeps_signed_options(self):
        original = source_call('substring',
            {'values': {'object': 'shared-object', 'field': 'value'}},
            substring_start=1, substring_length=-1)
        result = lower_expression(original)
        self.assertEqual(result, {'substring': {
            'substring_start': 1,
            'substring_length': -1,
            'value': {'concat': [
                {'literal': ''},
                {'values': {'object': 'shared-object', 'field': 'value'}}
            ]}}})
        # 0.3 source model's one-based start and negative remainder semantics.
        self.assertEqual('abcdef'[max(3, 1) - 1:], 'cdef')
        self.assertEqual('abcdef'[max(0, 1) - 1:max(0, 1) - 1 + 2], 'ab')
        self.assertGreaterEqual(99 - 1, len('abcdef'))  # source error branch

    def test_literal_source_is_not_rewritten_or_coerced(self):
        for name, options in (
            ('split', {'delimiter': ','}),
            ('substring', {'substring_start': 1, 'substring_length': 2}),
        ):
            with self.subTest(name=name):
                value = {'literal': {'datatype': 'string', 'value': 'a,b'}}
                self.assertEqual(lower_expression(source_call(name, value, **options)),
                                 {name: {**options, 'value': value}})
        # An explicit integer literal is *not* silently stringified by the
        # converter: the 0.4.1 semantic validator will still diagnose it.
        raw = {'literal': {'datatype': 'integer', 'value': 9}}
        self.assertEqual(lower_expression(source_call('split', raw, delimiter=',')),
                         {'split': {'delimiter': ',', 'value': raw}})

    def test_unique_port_retains_scalar_datatypes_and_source_order(self):
        source = {'function': {'name': 'unique', 'arguments': [
            {'literal': {'datatype': 'integer', 'value': 1}},
            {'literal': {'datatype': 'string', 'value': '1'}},
            {'literal': {'datatype': 'integer', 'value': 1}},
        ], 'options': {}}}
        self.assertEqual(lower_expression(source), {'unique': [
            {'literal': {'datatype': 'integer', 'value': 1}},
            {'literal': {'datatype': 'string', 'value': '1'}},
            {'literal': {'datatype': 'integer', 'value': 1}},
        ]})
        # 0.3's static evaluator stringified unique values. That is
        # insufficient proof of mixed-datatype OVAL equality, so we do NOT
        # copy its lossy equality rule into 0.4.1.

    def test_bad_legacy_shapes_are_still_rejected(self):
        for item in (
            {'function': {'name': 'split', 'arguments': [], 'options': {'delimiter': ','}}},
            {'function': {'name': 'substring', 'arguments': [{'values': {}}],
                          'options': {'substring_start': 1}}},
            {'function': {'name': 'unique', 'arguments': [], 'options': {}}},
        ):
            with self.subTest(item=item), self.assertRaisesRegex(ValueError, 'requires|invalid'):
                lower_expression(item)


if __name__ == '__main__':
    unittest.main()
