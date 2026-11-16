"""Exact finite-set XCCDF Input relation projection and fail-closed witnesses."""
import unittest
from copy import deepcopy

from scap_ng_tools.converter.native041_input_relation import project_input_relation


def document(values, operation, bound, datatype='integer'):
    return {'assessment': {'id': 'example', 'inputs': {'value-input': {
        'datatype': datatype, 'cardinality': 'exactly_one', 'required': True,
        'constraints': {'allowed': values, 'relation': {
            'operator': operation, 'value': bound}}}}}}


class FiniteSetXccdfInput(unittest.TestCase):
    def test_five_pinned_windows_2016_source_cases_preserve_all_membership(self):
        cases = [
            ([3, 5, 10, 50], 'less_than_or_equal', 3, [3]),         # SV-224867
            ([900, 3600, 86400], 'greater_than_or_equal', 900, [900, 3600, 86400]), # SV-224868
            ([5, 24], 'greater_than_or_equal', 24, [24]),          # SV-224869
            ([5184000, 7776000], 'less_than_or_equal', 5184000, [5184000]), # SV-224870
            ([86400, 172800, 432000], 'greater_than_or_equal', 86400, [86400, 172800, 432000]), # SV-224871
        ]
        pred = {'less_than': lambda x,y: x<y, 'less_than_or_equal': lambda x,y: x<=y,
                'greater_than': lambda x,y: x>y, 'greater_than_or_equal': lambda x,y: x>=y}
        for allowed, operation, bound, expected in cases:
            with self.subTest(operation=operation, bound=bound):
                candidate = document(allowed, operation, bound)
                receipts = project_input_relation(candidate)
                observed = candidate['assessment']['inputs']['value-input']['constraints']['allowed']
                self.assertEqual(observed, expected)
                self.assertEqual(receipts[0]['source_relation']['value'], bound)
                self.assertEqual(receipts[0]['original_allowed'], allowed)
                self.assertFalse(receipts[0]['scanner_equivalence'])
                for value in allowed + [bound-1, bound, bound+1, -1, 9999999]:
                    self.assertEqual(value in allowed and pred[operation](value, bound),
                                     value in observed)
                self.assertEqual(project_input_relation(candidate), [])

    def test_unsupported_forms_fail_closed_and_do_not_mutate(self):
        bad = [document([], 'less_than', 5), document([1, 2], 'less_than', 0),
               document([1, '2'], 'less_than', 4), document([True], 'less_than', 4),
               document([1, 2], 'less_than', 4, 'string'),
               document([1, 2], 'equals', 4), document([1, 2], 'less_than', 4.0)]
        for candidate in bad:
            with self.subTest(candidate=candidate):
                before = deepcopy(candidate)
                with self.assertRaises(ValueError):
                    project_input_relation(candidate)
                self.assertEqual(candidate, before)
        one = document([1, 2], 'less_than', 2)
        one['assessment']['inputs']['broken-input'] = {
            'datatype': 'integer', 'constraints': {'allowed': [1],
            'relation': {'operator': 'greater_than', 'value': 5}}}
        before = deepcopy(one)
        with self.assertRaisesRegex(ValueError, 'no permitted values'):
            project_input_relation(one)
        self.assertEqual(one, before)

    def test_non_input_data_is_opaque(self):
        data = {'assessment': {'inputs': {}, 'tests': {'test': {'require': {
            'fields': {'relation': {'operator': 'less_than', 'value': 1}}}}}}}
        before = deepcopy(data)
        self.assertEqual(project_input_relation(data), [])
        self.assertEqual(data, before)


if __name__ == '__main__':
    unittest.main()
