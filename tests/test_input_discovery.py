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
        provided = bind_inputs(contract, {'value-input': {'state': 'provided', 'source': 'test', 'values': []}}, invocation_id='empty')
        self.assertEqual(provided.state('value-input'), 'true')
        with self.assertRaises(PendingInputBinding):
            pending = bind_inputs(contract, {'value-input': {'state': 'pending', 'source': 'test', 'reason': 'waiting'}}, invocation_id='pending2')
            pending.state('value-input')
