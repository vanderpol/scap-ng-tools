"""Pure native discovery index; no validation/scanner claim from derivation alone."""
from copy import deepcopy
import unittest
from scap_ng_tools.authoring.input_discovery import derive_choice,input_locations,validate_choice_map


class NativeInputDiscovery(unittest.TestCase):
    def test_real_refs_guards_escaped_fields_and_literal_data(self):
        for name in ('a/b~c','description','constraints','title','literal','input','input_provided'):
            a={'inputs':{'value-input':{'required':False}},
               'tests':{'record-test':{'require':{'fields':{'value':{'record':{'fields':{name:{'equals':{'input':'value-input'}}}}}}}}},
               'variables':{'data-variable':{'expression':{'literal':{'datatype':'record','value':{'input':'not-a-reference-input'}}}}},
               'evaluate':{'if':{'input_provided':'value-input'}}}
            before=deepcopy(a);rows=derive_choice(a,{'value-input':'parameter'},{'parameter':{'resolution':'organization'}})
            self.assertEqual(a,before);self.assertEqual(len(rows),1);self.assertFalse(rows[0]['required'])
            self.assertEqual(len(rows[0]['uses']),2)
            path='/tests/record-test/require/fields/value/record/fields/'+name.replace('~','~0').replace('/','~1')+'/equals/input'
            self.assertIn({'kind':'value','source_path':path},rows[0]['uses'])
            self.assertEqual(len(input_locations(a)),2)

    def test_shared_parameter_requirement_and_publisher_exclusion(self):
        a={'inputs':{'first-input':{'required':False},'second-input':{'required':True}},
           'evaluate':{'if':{'input_provided':'first-input'},'then':{'input_provided':'second-input'}}}
        row=derive_choice(a,{'first-input':'parameter','second-input':{'parameter':'parameter'}},{'parameter':{'resolution':'organization'}})[0]
        self.assertTrue(row['required']);self.assertEqual(len(row['uses']),2)
        self.assertEqual(derive_choice(a,{'first-input':'parameter','second-input':'parameter-two'}, {'parameter':{'resolution':'publisher'}, 'parameter-two':{'resolution':'publisher'}}),[])

    def test_constraint_datatype_operation_matrix_rejects_invalid_source_operations(self):
        from scap_ng_tools.converter._v04_semantic.v04_input_presence import input_contracts
        invalid = [
            ('string', {'greater_than': 'x'}),
            ('boolean', {'bitwise_and': True}),
            ('integer', {'subset_of': 1}),
        ]
        for datatype, predicate in invalid:
            with self.subTest(datatype=datatype):
                with self.assertRaises(ValueError):
                    input_contracts({'inputs': {
                        'value-input': {'datatype': datatype, 'cardinality': 'exactly_one',
                                        'required': True, 'constraints': {'predicate': predicate}}}})

    def test_production_source_comparison_rejects_invalid_datatype_operations(self):
        import sys
        from pathlib import Path
        runtime = Path(__file__).resolve().parents[1] / 'src/scap_ng_tools/converter/_v04_runtime'
        sys.path.insert(0, str(runtime))
        try:
            from v04_direct_datatypes import comparison
            with self.assertRaises(ValueError):
                comparison('string', 'greater than', 'greater_than')
            with self.assertRaises(ValueError):
                comparison('boolean', 'bitwise and', 'bitwise_and')
            with self.assertRaises(ValueError):
                comparison('int', 'subset of', 'subset_of')
            self.assertEqual(comparison('int', 'bitwise and', 'bitwise_and'), 'bitwise_and')
        finally:
            sys.path.remove(str(runtime))

    def test_publisher_default_uses_shared_typed_constraint_evaluator(self):
        import sys
        from pathlib import Path
        runtime = Path(__file__).resolve().parents[1] / 'src/scap_ng_tools/converter/_v04_runtime'
        sys.path.insert(0, str(runtime))
        try:
            from v04_draft_inputs import _value_satisfies_constraints
            self.assertTrue(_value_satisfies_constraints(
                '1.2.3', {'predicate': {'version_greater_than': '1.2.0'}}))
            self.assertTrue(_value_satisfies_constraints(
                '00FF', {'predicate': {'binary_equals': '00ff'}}))
            self.assertFalse(_value_satisfies_constraints(
                '1.2.3', {'predicate': {'version_less_than': '1.2.0'}}))
        finally:
            sys.path.remove(str(runtime))


if __name__=='__main__':unittest.main()

class NativeInputDiscoveryContracts(unittest.TestCase):
    def setUp(self):
        self.assessment = {
            'inputs': {
                'value-input': {
                    'datatype': 'integer', 'cardinality': 'exactly_one', 'required': False,
                },
                'required-input': {
                    'datatype': 'string', 'cardinality': 'zero_or_one', 'required': True,
                },
            },
            'tests': {
                'registry-test': {
                    'require': {'fields': {'value': {'equals': {'input': 'value-input'}}}},
                },
            },
            'evaluate': {
                'if': {'input_provided': 'value-input'},
                'then': {'test': 'registry-test'},
                'else': {'not_evaluated': 'missing'},
            },
        }
        self.parameters = {
            'org-value': {'id': 'org-value', 'datatype': 'integer', 'cardinality': 'exactly_one',
                          'resolution': 'organization'},
            'required-param': {'id': 'required-param', 'datatype': 'string', 'cardinality': 'zero_or_one',
                               'resolution': 'organization'},
        }
        self.bindings = {
            'value-input': {'parameter': 'org-value'},
            'required-input': {'parameter': 'required-param'},
        }

    def test_derived_map_and_exact_packaged_map(self):
        expected = derive_choice(self.assessment, self.bindings, self.parameters)
        self.assertEqual(expected[0]['input'], 'org-value')
        self.assertEqual({u['kind'] for u in expected[0]['uses']}, {'value', 'presence'})
        self.assertEqual(validate_choice_map(self.assessment, self.bindings, self.parameters, expected), expected)
        with self.assertRaisesRegex(ValueError, 'exactly match'):
            validate_choice_map(self.assessment, self.bindings, self.parameters, [])

    def test_optional_unbound_is_allowed_but_required_binding_is_not(self):
        bindings = {'required-input': {'parameter': 'required-param'}}
        self.assertEqual(derive_choice(self.assessment, bindings, self.parameters), [])
        with self.assertRaisesRegex(ValueError, 'required Input'):
            derive_choice(self.assessment, {'value-input': {'parameter': 'org-value'}}, self.parameters)

    def test_unknown_binding_parameter_and_type_or_cardinality_mismatch_reject(self):
        cases = [
            ({'unknown-input': {'parameter': 'org-value'}}, 'unknown Assessment Input'),
            ({**self.bindings, 'value-input': {'parameter': 'missing'}}, 'nonexistent Benchmark Parameter'),
        ]
        for bindings, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                derive_choice(self.assessment, bindings, self.parameters)
        bad_type = dict(self.parameters)
        bad_type['org-value'] = {**bad_type['org-value'], 'datatype': 'string'}
        with self.assertRaisesRegex(ValueError, 'datatype mismatch'):
            derive_choice(self.assessment, self.bindings, bad_type)
        bad_card = dict(self.parameters)
        bad_card['org-value'] = {**bad_card['org-value'], 'cardinality': 'zero_or_more'}
        with self.assertRaisesRegex(ValueError, 'cardinality mismatch'):
            derive_choice(self.assessment, self.bindings, bad_card)

    def test_pointer_integrity_kind_input_and_exact_multiset_are_fail_closed(self):
        expected = derive_choice(self.assessment, self.bindings, self.parameters)
        bad_cases = []
        wrong_path = deepcopy(expected)
        wrong_path[0]['uses'][0]['source_path'] = '/evaluate/if/~2bad'
        bad_cases.append(wrong_path)
        duplicate = deepcopy(expected)
        duplicate[0]['uses'].append(deepcopy(duplicate[0]['uses'][0]))
        bad_cases.append(duplicate)
        wrong_kind = deepcopy(expected)
        wrong_kind[0]['uses'][0]['kind'] = 'value'
        bad_cases.append(wrong_kind)
        wrong_parameter = deepcopy(expected)
        wrong_parameter[0]['input'] = 'required-param'
        bad_cases.append(wrong_parameter)
        for candidate in bad_cases:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                validate_choice_map(self.assessment, self.bindings, self.parameters, candidate)

    def test_rfc6901_escaped_record_member_and_array_pointer(self):
        assessment = {
            'inputs': {'value-input': {'datatype': 'string', 'cardinality': 'exactly_one', 'required': False}},
            'tests': {'record-test': {'require': {'fields': {'record': {'record': {
                'a/b~c': {'equals': {'input': 'value-input'}}}}}}}},
            'evaluate': {'if': {'input_provided': 'value-input'}, 'then': {'test': 'record-test'},
                        'else': {'not_evaluated': 'missing'}},
        }
        parameters = {'org-value': {'datatype': 'string', 'cardinality': 'one', 'resolution': 'organization'}}
        bindings = {'value-input': 'org-value'}
        rows = derive_choice(assessment, bindings, parameters)
        self.assertIn('/tests/record-test/require/fields/record/record/a~1b~0c/equals/input',
                      {u['source_path'] for u in rows[0]['uses']})

class NativeInputPresenceSemantics(unittest.TestCase):
    def test_optional_consumer_requires_direct_presence_guard(self):
        from scap_ng_tools.converter._v04_semantic.v04_input_presence import presence_contract
        assessment = {
            'inputs': {'value-input': {'datatype': 'integer', 'cardinality': 'zero_or_one', 'required': False}},
            'tests': {'value-test': {'require': {'fields': {'value': {'equals': {'input': 'value-input'}}}}}},
            'evaluate': {'test': 'value-test'},
        }
        with self.assertRaisesRegex(ValueError, 'unguarded optional Input'):
            presence_contract(assessment)

    def test_binding_states_keep_omitted_empty_unknown_error_pending_distinct(self):
        from scap_ng_tools.converter._v04_semantic.v04_input_presence import bind_inputs, PendingInputBinding
        contract = {'value-input': {'datatype': 'integer', 'cardinality': 'zero_or_more', 'required': False}}
        states = {}
        for state in ('omitted', 'unknown', 'error', 'pending'):
            entry = {'state': state, 'source': 'test'}
            if state != 'omitted':
                entry['reason'] = state + ' reason'
            snapshot = bind_inputs(contract, {'value-input': entry}, invocation_id=state)
            states[state] = snapshot.state('value-input') if state != 'pending' else None
        self.assertEqual(states, {'omitted': 'false', 'unknown': 'unknown', 'error': 'error', 'pending': None})
        required = bind_inputs(
            {'required-input': {'datatype': 'string', 'cardinality': 'exactly_one', 'required': True}},
            {'required-input': {'state': 'omitted', 'source': 'test'}},
            invocation_id='required-omitted')
        self.assertEqual(required.state('required-input'), 'not_evaluated')
        provided = bind_inputs(contract, {'value-input': {'state': 'provided', 'source': 'test', 'values': []}}, invocation_id='empty')
        self.assertEqual(provided.state('value-input'), 'true')
        with self.assertRaises(PendingInputBinding):
            pending = bind_inputs(contract, {'value-input': {'state': 'pending', 'source': 'test', 'reason': 'waiting'}}, invocation_id='pending2')
            pending.state('value-input')

class NativeInputRestrictionBinding(unittest.TestCase):
    def setUp(self):
        from scap_ng_tools.converter._v04_semantic.v04_input_presence import bind_inputs
        self.bind_inputs = bind_inputs

    @staticmethod
    def contract(predicate, *, cardinality='one_or_more', datatype='integer'):
        return {'value-input': {'datatype': datatype, 'cardinality': cardinality,
                                'required': True, 'constraints': {'predicate': predicate}}}

    def bind(self, contract, values, name='restriction'):
        return self.bind_inputs(contract, {'value-input': {
            'state': 'provided', 'source': 'test', 'values': values}}, invocation_id=name)

    def test_multivalue_predicate_requires_every_supplied_value_to_match(self):
        contract = self.contract({'greater_than_or_equal': 2})
        self.assertEqual(self.bind(contract, [2, 3]).state('value-input'), 'true')
        self.assertEqual(self.bind(contract, [2, 1]).state('value-input'), 'error')
        # A valid explicit empty population remains distinct from omission and
        # is valid for one_or_more only when the contract is changed to allow it.
        empty = self.bind_inputs(
            self.contract({'equals': 2}, cardinality='zero_or_more'),
            {'value-input': {'state': 'provided', 'source': 'test', 'values': []}},
            invocation_id='empty')
        self.assertEqual(empty.state('value-input'), 'true')

    def test_all_boolean_restriction_operators_are_executed(self):
        vectors = {
            'and': ([{'equals': 2}, {'greater_than': 1}], True),
            'or': ([{'equals': 2}, {'equals': 4}], True),
            'one': ([{'equals': 2}, {'equals': 3}], True),
            'xor': ([{'equals': 2}, {'equals': 3}], True),
        }
        for operator, (branches, expected) in vectors.items():
            with self.subTest(operator=operator):
                result = self.bind(self.contract({operator: branches}), [2], operator)
                self.assertEqual(result.state('value-input'), 'true' if expected else 'error')

    def test_negative_restriction_and_malformed_predicate_fail_closed(self):
        rejected = self.bind(self.contract({'less_than': 2}), [2], 'negative')
        self.assertEqual(rejected.state('value-input'), 'error')
        from scap_ng_tools.converter._v04_semantic.v04_input_presence import input_contracts
        with self.assertRaises(ValueError):
            input_contracts({'inputs': self.contract({'and': []})})
        with self.assertRaises(ValueError):
            input_contracts({'inputs': self.contract({'matches_regex': '['}, datatype='string')})

class NativeTypedInputRestrictionBinding(unittest.TestCase):
    def setUp(self):
        from scap_ng_tools.converter._v04_semantic.v04_input_presence import bind_inputs
        self.bind_inputs = bind_inputs

    def check(self, datatype, operation, bound, value, expected='true'):
        contract = {'typed-input': {'datatype': datatype, 'cardinality': 'exactly_one',
                                    'required': True,
                                    'constraints': {'predicate': {operation: bound}}}}
        snapshot = self.bind_inputs(contract, {'typed-input': {
            'state': 'provided', 'source': 'test', 'values': [value]}},
                                    invocation_id=operation)
        self.assertEqual(snapshot.state('typed-input'), expected)

    def test_typed_equality_and_ordering_boundaries(self):
        self.check('binary', 'binary_equals', '00ff', '00FF')
        self.check('version', 'version_greater_than', '1.2.3', '1.2.4')
        self.check('float', 'float_greater_than_or_equal', 1.5, 1.5)
        self.check('ipv4', 'ipv4_subset_of', '192.0.2.0/24', '192.0.2.0/25')
        self.check('rpm_evr', 'rpm_evr_equals', '0:1-1', '0:1-1')
        self.check('debian_evr', 'debian_evr_equals', '0:1-1', '0:1-1')
        self.check('fileset_revision', 'fileset_revision_equals', 'A.03.61.00', 'A.03.61.00')
        self.check('ios_version', 'ios_version_equals', '15.1', '15.1')

    def test_integer_bitwise_constraints(self):
        self.check('integer', 'bitwise_and', 4, 6)
        self.check('integer', 'bitwise_or', 14, 1, expected='error')
