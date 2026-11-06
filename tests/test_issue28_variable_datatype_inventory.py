"""Regression gates for the exhaustive Issue #28 datatype audit.

The source ZIPs are intentionally not test fixtures.  The committed audit
artifact carries their hashes and source-preserving declarations; this test
keeps the generated inventory deterministic and exercises the pinned OVAL
boundary vectors independently of the converter.
"""
from __future__ import annotations

import gzip
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / 'docs/evidence/issue28/OVAL-VARIABLE-DATATYPE-INVENTORY.json.gz'


def load_audit_script():
    spec = importlib.util.spec_from_file_location(
        'audit_issue28_variable_datatypes', ROOT / 'scripts/audit_issue28_variable_datatypes.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class VariableDatatypeInventory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with gzip.open(INVENTORY, 'rt', encoding='utf-8') as stream:
            cls.audit = json.load(stream)
        cls.variables = [v for b in cls.audit['benchmarks'] for v in b['variables']]

    def test_complete_source_scope_and_variable_counts(self):
        self.assertEqual(self.audit['scope']['benchmarks'], 65)
        self.assertEqual(self.audit['scope']['rules'], 8892)
        self.assertEqual(len(self.audit['benchmarks']), 65)
        self.assertEqual(len(self.variables), 2385)
        self.assertEqual(self.audit['inventory']['variable_counts'], {
            'constant_variable': 552,
            'external_variable': 436,
            'local_variable': 1397,
        })
        self.assertTrue(all(len(b['source_sha256']) == 64 for b in self.audit['benchmarks']))
        self.assertEqual(sum(b['source_rules'] for b in self.audit['benchmarks']), 8892)

    def test_function_occurrences_and_result_domains_are_pinned(self):
        self.assertEqual(self.audit['inventory']['function_occurrences'], {
            'arithmetic': 9, 'concat': 750, 'count': 47, 'end': 3,
            'merge': 106, 'regex_capture': 320, 'split': 29,
            'substring': 21, 'unique': 63,
        })
        self.assertEqual(self.audit['oval_contract']['function_result_domains']['count'], ['integer'])
        self.assertEqual(self.audit['oval_contract']['function_result_domains']['split'], ['string'])
        self.assertEqual(self.audit['oval_contract']['function_result_domains']['substring'], ['string'])
        self.assertEqual(self.audit['oval_contract']['function_result_domains']['arithmetic'], ['integer', 'float'])

    def test_all_function_declarations_preserve_source_xml_and_cardinality(self):
        function_variables = [v for v in self.variables if v['functions']]
        self.assertEqual(len(function_variables), 1185)
        self.assertTrue(all(v['source_xml'] for v in function_variables))
        self.assertTrue(all(v['source_datatype_token'] for v in function_variables))
        for variable in function_variables:
            names = {f['name'] for f in variable['functions']}
            if 'count' in names and variable['root_expression'] == 'count':
                self.assertEqual(variable['inferred_cardinality'], 'single')
            if variable['root_expression'] == 'split':
                self.assertEqual(variable['inferred_cardinality'], 'collection')

    def test_mismatch_inventory_is_fail_closed(self):
        mismatches = self.audit['inventory']['mismatches']
        self.assertEqual(len(mismatches), 31)
        self.assertEqual(len({r for m in mismatches for r in m['rules']}), 13)
        self.assertEqual({m['function'] for m in mismatches}, {
            'arithmetic', 'concat', 'count', 'merge', 'regex_capture', 'split', 'substring'})
        self.assertFalse(self.audit['qualification']['declarations_overridden'])
        self.assertFalse(self.audit['qualification']['implicit_casts_added'])
        self.assertFalse(self.audit['qualification']['mismatch_rules_promoted'])
        self.assertEqual(self.audit['inventory']['dependency_audit']['unresolved_references'], [])
        self.assertEqual(self.audit['inventory']['dependency_audit']['cycle_count'], 0)

    def test_oval_lexical_boundary_vectors(self):
        audit = load_audit_script()
        self.assertTrue(audit.lexical_valid('+001', 'int'))
        self.assertTrue(audit.lexical_valid('0', 'boolean'))
        self.assertTrue(audit.lexical_valid('1.0e+3', 'float'))
        self.assertFalse(audit.lexical_valid('', 'int'))
        self.assertFalse(audit.lexical_valid('x', 'int'))

    def test_independent_oval_collection_vectors(self):
        # These vectors encode the pinned OVAL documentation, rather than
        # native converter behavior: split retains empty tokens, count flattens
        # represented values, and arithmetic expands the Cartesian product.
        self.assertEqual('-a-a-'.split('-'), ['', 'a', 'a', ''])
        self.assertEqual('---'.split('-'), ['', '', '', ''])
        self.assertEqual(sum(len(values) for values in [[], ['a'], ['b', 'c']]), 3)
        self.assertEqual([a + b for a in [1, 2] for b in [3, 4, 5]],
                         [4, 5, 6, 5, 6, 7])
        # A failed explicit integer conversion is an error, never a default.
        with self.assertRaises(ValueError):
            int('x')


if __name__ == '__main__':
    unittest.main()
