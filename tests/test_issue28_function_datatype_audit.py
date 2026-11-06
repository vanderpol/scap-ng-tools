"""The eight source datatype conflicts remain blocked pending owner policy."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class FunctionDatatypeAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit = json.loads((ROOT / 'docs/evidence/issue28/OVAL-FUNCTION-DATATYPE-AUDIT.json').read_text())

    def test_exactly_eight_records_and_no_recovery_claim(self):
        self.assertEqual(len(self.audit['records']), 8)
        self.assertEqual(self.audit['conclusion'], {
            'recoverable_without_new_native_cast': 0,
            'requires_owner_cast_decision': 8,
            'source_declarations_overridden': False,
            'implicit_casts_added': False,
            'rules_promoted': False,
        })

    def test_function_result_domains_and_declared_domains_conflict(self):
        pairs = {(r['function'], r['declared_datatype'], r['function_output_datatype'])
                 for r in self.audit['records']}
        self.assertIn(('arithmetic', 'string', 'integer or float'), pairs)
        self.assertIn(('split', 'int', 'string'), pairs)
        self.assertIn(('count', 'string', 'integer'), pairs)
        for record in self.audit['records']:
            self.assertTrue(record['original_variable_xml'])
            self.assertIn('success', record['representative_values'])
            self.assertIn('error', record['representative_values'])

if __name__ == '__main__':
    unittest.main()
