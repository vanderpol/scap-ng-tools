"""SCAP-NG 0.4.1: recovered OVAL functions must use the active native grammar.

These are syntax/provenance witnesses, not executable OVAL or RI equivalence.
Multi-component count is deliberately blocked until a lossless mapping exists.
"""
import unittest
import xml.etree.ElementTree as ET

from scap_ng_tools.converter.direct04 import load_runtime
from scap_ng_tools.converter.native041_function_lowering import lower_expression, lower_assessment_inplace
from scap_ng_tools.converter.native041_variable_result_type import result_type

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
        original = visitor.function(source)
        self.assertIn('function', original)  # immutable source visitor
        value = lower_expression(original)
        self.assertEqual(value, {'count': {'unique': [
            {'literal': {'datatype': 'string', 'value': 'alpha'}},
            {'literal': {'datatype': 'string', 'value': 'alpha'}},
            {'literal': {'datatype': 'string', 'value': 'beta'}},
        ]}})
        self.assertNotIn('function', str(value))
        self.assertEqual(visitor.conversion_warnings[0]['independent_static_proof'], 'UNPROVED')
        self.assertFalse(visitor.conversion_warnings[0]['scanner_evaluated'])

    def test_direct_source_unique_projects_only_collected_item_values(self):
        class Source:
            native_recovery = True
            def __init__(self, object_node):
                self.object_node = object_node
            def node(self, _component, identifier, _kind):
                return self.object_node

        object_node = ET.fromstring('<shellcommand_object xmlns="' + OVAL + '#independent" id="obj-1"/>')
        mapping = {'capability': 'independent.shellcommand',
                   'source': {'namespace': OVAL + '#independent',
                              'object': 'shellcommand_object'},
                   'native': {'test_source': {'kind': 'object'},
                              'state_field_map': {'subexpression': 'subexpression'}}}
        visitor = AssessmentConverter(Source(object_node), 'component', [mapping], native_recovery=True)
        visitor.reference = lambda _identifier, _kind: {
            'capability': 'independent.shellcommand', 'command': 'printf x'}
        source = oval('<unique xmlns="OVAL"><object_component object_ref="obj-1" item_field="subexpression"/></unique>')
        self.assertEqual(visitor.function(source), {'unique': {'concat': [
            {'literal': ''}, {'values': {
                'object': {'capability': 'independent.shellcommand', 'command': 'printf x'},
                'field': 'subexpression'}}]}})

    def test_time_difference_uses_active_typed_expression_for_all_formats_and_arities(self):
        visitor = self.visitor()
        cases = [
            ('year_month_day', 'year_month_day',
             '<literal_component datatype="string">2009-02-04</literal_component>',
             '<literal_component datatype="string">2004-02-04</literal_component>'),
            ('month_day_year', 'month_day_year',
             '<literal_component datatype="string">02/04/2009</literal_component>',
             '<literal_component datatype="string">02/04/2004</literal_component>'),
            ('day_month_year', 'month_day_year',
             '<literal_component datatype="string">04/02/2009</literal_component>',
             '<literal_component datatype="string">02/04/2004</literal_component>'),
            ('seconds_since_epoch', 'seconds_since_epoch',
             '<literal_component datatype="int">1238506200</literal_component>',
             '<literal_component datatype="int">1238420000</literal_component>'),
            ('day_month_year', 'win_filetime',
             '<literal_component datatype="string">1/1/1970</literal_component>',
             '<literal_component datatype="string">19db1ded53e8000</literal_component>'),
        ]
        for format_1, format_2, left, right in cases:
            with self.subTest(format_1=format_1, format_2=format_2):
                source = oval(
                    f'<time_difference xmlns="OVAL" format_1="{format_1}" format_2="{format_2}">'
                    f'{left}{right}</time_difference>')
                native = visitor.function(source)
                self.assertEqual(native['time_difference']['format_1'], format_1)
                self.assertEqual(native['time_difference']['format_2'], format_2)
                self.assertEqual(lower_expression(native), native)

        one = oval('<time_difference xmlns="OVAL" format_1="month_day_year" format_2="seconds_since_epoch">'
                   '<literal_component datatype="int">1238506200</literal_component>'
                   '</time_difference>')
        self.assertEqual(visitor.function(one), {
            'time_difference': {
                'format_1': 'month_day_year',
                'format_2': 'seconds_since_epoch',
                'values': [{'literal': {'datatype': 'integer', 'value': 1238506200}}],
            },
        })
        default = oval('<time_difference xmlns="OVAL"><literal_component datatype="string">2009-02-04</literal_component>'
                       '</time_difference>')
        self.assertEqual(visitor.function(default), {
            'time_difference': {
                'values': [{'literal': {'datatype': 'string', 'value': '2009-02-04'}}],
            },
        })

    def test_time_difference_keeps_nested_graphs_and_rejects_invalid_shape(self):
        nested = {
            'time_difference': {
                'values': [
                    {'variable': 'left-variable'},
                    {'values': {'object': {'object_ref': 'source-object'}, 'field': 'value'}},
                ],
                'format_1': 'year_month_day',
                'format_2': 'seconds_since_epoch',
            },
        }
        self.assertEqual(lower_expression(nested), nested)
        self.assertEqual(lower_expression({'time_difference': {
            'values': [{'literal': '2009-02-04'}],
            'format_1': 'seconds_since_epoch',
            'format_2': 'year_month_day',
        }}), {'time_difference': {
            'values': [{'literal': '2009-02-04'}],
            'format_1': 'seconds_since_epoch',
            'format_2': 'year_month_day',
        }})
        with self.assertRaisesRegex(ValueError, 'time_difference has unsupported format'):
            lower_expression({'time_difference': {
                'values': [{'literal': '2009-02-04'}, {'literal': '2004-02-04'}],
                'format_1': 'cim_datetime',
                'format_2': 'year_month_day',
            }})
        with self.assertRaisesRegex(ValueError, 'one or two operands'):
            lower_expression({'time_difference': {
                'values': [],
            }})

    def test_native_arithmetic_preserves_order_and_numeric_literal_types(self):
        visitor = self.visitor()
        source = oval(
            '<arithmetic xmlns="OVAL" arithmetic_operation="multiply">'
            '<literal_component datatype="int">2</literal_component>'
            '<literal_component datatype="int">3</literal_component>'
            '</arithmetic>')
        self.assertEqual(lower_expression(visitor.function(source)), {
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
                expression = lower_expression(visitor.function(source))
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
            lower_expression(visitor.function(source))

    def test_document_lowering_is_atomic_on_unrepresentable_source(self):
        source = {
            'assessment': {
                'variables': {
                    'safe-variable': {
                        'kind': 'local',
                        'expression': {'function': {'name': 'count', 'arguments': [
                            {'literal': ['a', 'b']}
                        ], 'options': {}}},
                    },
                    'blocked-variable': {
                        'kind': 'local',
                        'expression': {'function': {'name': 'count', 'arguments': [
                            {'literal': 'a'}, {'literal': 'b'}
                        ], 'options': {}}},
                },
            },
        }
        }
        before = repr(source)
        with self.assertRaisesRegex(ValueError, 'multi-component OVAL count'):
            lower_assessment_inplace(source)
        self.assertEqual(repr(source), before)

    def test_document_lowering_preserves_other_assessment_fields(self):
        source = {'assessment': {
            'id': 'test-assessment',
            'tests': {'test-name': {'test_title': 'Test'}},
            'variables': {'count-variable': {
                'kind': 'local', 'expression': {'function': {'name': 'count',
                    'arguments': [{'literal': ['a', 'a']}], 'options': {}}}}
        }}}
        self.assertTrue(lower_assessment_inplace(source))
        self.assertEqual(source['assessment']['variables']['count-variable']['expression'],
                         {'count': {'literal': ['a', 'a']}})
        self.assertEqual(source['assessment']['tests'], {'test-name': {'test_title': 'Test'}})
        self.assertFalse(lower_assessment_inplace(source))

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

class StaticVariableObjectSetRecovery(unittest.TestCase):
    def visitor(self, nodes, values):
        class Source:
            native_recovery = True
            def node(self, _component, identifier, _kind):
                return nodes[identifier]
        visitor = AssessmentConverter(Source(), 'component', [], native_recovery=True)
        visitor.reference = lambda identifier, _kind: values[identifier]
        visitor.native_name = lambda _element, _kind, title=None: 'static-set-variable'
        return visitor

    def test_base_namespace_var_ref_and_nested_sets_materialize_in_source_order(self):
        objects = {
            'left': oval('<variable_object xmlns="OVAL" id="left"><var_ref>one</var_ref></variable_object>'),
            'right': oval('<variable_object xmlns="OVAL" id="right"><var_ref>two</var_ref></variable_object>'),
            'nested': oval('<variable_object xmlns="OVAL" id="nested"><set set_operator="INTERSECTION">'
                           '<object_reference>left</object_reference><object_reference>right</object_reference>'
                           '</set></variable_object>'),
            'one': oval('<constant_variable xmlns="OVAL" id="one"/>'),
            'two': oval('<constant_variable xmlns="OVAL" id="two"/>'),
            'root': oval('<variable_object xmlns="OVAL" id="root"><set set_operator="UNION">'
                         '<object_reference>nested</object_reference><object_reference>left</object_reference>'
                         '</set></variable_object>'),
        }
        visitor = self.visitor(objects, {'one': ['a', 'b'], 'two': ['b', 'c']})
        result = visitor.static_variable_object(objects['root'])
        self.assertEqual(result, {'variable': 'static-set-variable'})
        self.assertEqual(visitor.variables['static-set-variable'], {
            'kind': 'constant',
            'expression': {'literal': {'datatype': 'string', 'value': ['b', 'a']}}})
        self.assertEqual(visitor.conversion_warnings[0]['population_size'], 2)
        self.assertEqual(visitor.synthetic_variables[0]['source_variable_ids'], ['one', 'two'])
        self.assertEqual(visitor.synthetic_variables[0]['set_operator'], 'UNION')

    def test_filters_and_dynamic_variables_remain_held(self):
        objects = {
            'root': oval('<variable_object xmlns="OVAL" id="root"><set><object_reference>left</object_reference>'
                         '<filter action="include">state</filter></set></variable_object>'),
            'left': oval('<variable_object xmlns="OVAL" id="left"><var_ref>dynamic</var_ref></variable_object>'),
            'dynamic': oval('<local_variable xmlns="OVAL" id="dynamic"/>'),
        }
        visitor = self.visitor(objects, {'dynamic': {'variable': 'runtime-variable'}})
        with self.assertRaisesRegex(ValueError, 'filtered Variable Object Set'):
            visitor.static_variable_object(objects['root'])

        objects['root'] = oval('<variable_object xmlns="OVAL" id="root"><set><object_reference>left</object_reference>'
                               '<object_reference>right</object_reference></set></variable_object>')
        objects['right'] = oval('<variable_object xmlns="OVAL" id="right"><var_ref>dynamic</var_ref></variable_object>')
        with self.assertRaisesRegex(ValueError, 'not a static population'):
            visitor.static_variable_object(objects['root'])

    def test_variable_test_state_uses_expression_result_type_over_stale_declaration(self):
        visitor = AssessmentConverter(None, None, [], native_recovery=True)
        merge = oval(
            '<local_variable xmlns="OVAL" datatype="int" id="var-merge">'
            '<merge delimiter=":" sort="natural">'
            '<literal_component datatype="int">1</literal_component>'
            '</merge></local_variable>')
        self.assertEqual(result_type(merge), 'string')
        time_difference = oval(
            '<local_variable xmlns="OVAL" datatype="string" id="var-time">'
            '<time_difference format_2="seconds_since_epoch">'
            '<literal_component datatype="int">0</literal_component>'
            '</time_difference></local_variable>')
        self.assertEqual(result_type(time_difference), 'int')

    def test_literal_escape_regex_is_materialized_without_cast(self):
        visitor = AssessmentConverter(None, None, [], native_recovery=True)
        source = oval('<escape_regex xmlns="OVAL"><literal_component datatype="string">\\^.$|()[]{}*+?</literal_component></escape_regex>')
        self.assertEqual(visitor.function(source), {
            'literal': {'datatype': 'string',
                        'value': r'\\\^\.\$\|\(\)\[\]\{\}\*\+\?'}})
        self.assertEqual(visitor.conversion_warnings[-1]['independent_static_proof'],
                         'SOURCE_LITERAL_FUNCTION_LOWERING')

    def test_literal_glob_to_regex_matches_pinned_oval_vectors(self):
        visitor = AssessmentConverter(None, None, [], native_recovery=True)
        cases = [
            ('*.txt', '^(?=[^\\.])[^/]*\\.txt$'),
            ('x[[:digit:]]\\*', '^(?=[^\\.])x[[:digit:]]\\*$'),
            ('~/files/*.txt', '^(?=[^\\.])~/(?=[^\\.])files/(?=[^\\.])[^/]*\\.txt$'),
            ('\\*', '^(?=[^\\.])\\*$'),
        ]
        for pattern, expected in cases:
            with self.subTest(pattern=pattern):
                source = oval('<glob_to_regex glob_noescape="false" xmlns="OVAL">'
                              '<literal_component datatype="string">' + pattern +
                              '</literal_component></glob_to_regex>')
                self.assertEqual(visitor.function(source),
                                 {'literal': {'datatype': 'string', 'value': expected}})

    def test_literal_function_lowering_rejects_dynamic_and_invalid_inputs(self):
        class Source:
            native_recovery = True
            def node(self, _component, _identifier, _kind):
                return oval('<local_variable xmlns="OVAL" id="dynamic" datatype="string">'
                            '<object_component object_ref="obj" item_field="value"/>'
                            '</local_variable>')
        visitor = AssessmentConverter(Source(), 'component', [], native_recovery=True)
        source = oval('<glob_to_regex xmlns="OVAL"><variable_component var_ref="dynamic"/></glob_to_regex>')
        with self.assertRaisesRegex(ValueError, 'constant string Variable'):
            visitor.function(source)
        with self.assertRaisesRegex(ValueError, 'invalid glob_to_regex bracket'):
            from v04_direct_converter import glob_to_regex_literal
            glob_to_regex_literal('[unterminated')

class ClosedEnumDatatypeRecoveryTests(unittest.TestCase):
    def test_typed_literal_array_is_derived_and_projected_without_cast(self):
        from v04_direct_enum_variables import closed_enum_variable, variable_datatype

        class Visitor:
            component_id = 'component'
            used = {'source-variable': {'kind': 'variable'}}
            enum_variable_copies = {}
            enum_variable_equivalences = []
            variables = {
                'source-variable': {
                    'kind': 'constant',
                    'expression': {'literal': {
                        'datatype': 'string', 'value': ['alpha', 'beta']}}
                }
            }

            def named_variable(self, identifier):
                return identifier

            class source:
                @staticmethod
                def node(_component, identifier, _kind):
                    return ET.Element('variable', {'id': identifier, 'comment': 'source'})

        visitor = Visitor()
        self.assertEqual(variable_datatype(visitor, 'source-variable'), 'string')
        projected = closed_enum_variable(visitor, 'source-variable',
                                         {'alpha': 'a', 'beta': 'b'})
        name = projected['variable']
        self.assertEqual(visitor.variables[name]['expression'], {
            'literal': {'datatype': 'string', 'value': ['a', 'b']}})
        self.assertFalse('datatype' in visitor.variables[name])

if __name__ == '__main__':
    unittest.main()
