"""Reconciliation checks for the regenerated Issue #28 ledger."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / 'docs/evidence/issue28/COMPLETE-LEDGER.json'
INVENTORY = ROOT / 'docs/evidence/issue28/OVAL-SOURCE-INVENTORY.json'
MATRIX = ROOT / 'docs/evidence/issue28/OVAL-COVERAGE-MATRIX.json'


class Issue28CompleteLedger(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ledger = json.loads(LEDGER.read_text())
        cls.inventory = json.loads(INVENTORY.read_text())
        cls.matrix = json.loads(MATRIX.read_text())

    def test_mutually_exclusive_reconciliation(self):
        self.assertEqual(self.ledger['scope']['benchmarks'], 65)
        self.assertEqual(self.ledger['scope']['rules'], 8892)
        self.assertEqual(self.ledger['baseline']['total'], 8892)
        classification = self.ledger['classification']
        self.assertEqual(sum(classification[key] for key in (
            'automated_converted_proved', 'automated_converted_unproved',
            'manual_only', 'genuinely_blocked', 'intentionally_excluded')), 8892)
        self.assertEqual(classification['automated_converted_proved'], 0)
        self.assertEqual(classification['automated_converted_unproved'], 6785)
        self.assertEqual(classification['manual_only'], 1581)
        self.assertEqual(classification['genuinely_blocked'], 317)
        self.assertEqual(classification['intentionally_excluded'], 209)

    def test_deprecated_and_supported_wmi_stats_are_separate(self):
        stats = self.ledger['diagnostic_stats']
        self.assertEqual(stats['deprecated_oval_tests']['access_token']['source_rules_nonexcluded'], 127)
        self.assertEqual(stats['deprecated_oval_tests']['legacy_wmi']['source_rules_nonexcluded'], 37)
        self.assertEqual(stats['wmi57_supported']['source_rules_nonexcluded'], 169)
        self.assertEqual(stats['count_function']['source_rules_nonexcluded'], 37)
        self.assertEqual(stats['count_function']['primary_blocker_rules'], 37)

    def test_primary_blockers_are_stable_root_causes(self):
        for row in self.ledger['primary_blockers']:
            if row['category'] == 'schema-semantic':
                self.assertNotIn('authoring/direct-slice', row['message'])
                self.assertNotIn("'function':", row['message'])
        self.assertEqual(sum(row['rules'] for row in self.ledger['primary_blockers']), 317)

    def test_source_inventory_matches_owner_baseline(self):
        self.assertEqual(self.inventory['source_count'], 65)
        self.assertEqual(self.inventory['rule_count'], 8892)
        names = {row['name'] for row in self.inventory['operations']}
        self.assertTrue({'count', 'split', 'substring', 'concat', 'regex_capture',
                         'unique', 'merge', 'arithmetic', 'external_variable'} <= names)
        operations = {row['name']: row for row in self.inventory['operations']}
        for name in ('count', 'split', 'substring', 'arithmetic'):
            self.assertEqual(operations[name]['matrix_status'], 'partially_implemented')
        self.assertEqual(operations['filter']['category'], 'Object operation')
        self.assertEqual(operations['set']['category'], 'Object operation')
        self.assertEqual(operations['local_variable']['category'], 'Variable construct')
        self.assertEqual(operations['registry_test']['category'], 'Test capability')
        covered = {row['name']: row for row in self.matrix['operation_coverage']}
        self.assertEqual(set(covered), set(operations))
        self.assertTrue(all(row['status'] in self.matrix['status_vocabulary']
                            for row in covered.values()))
        self.assertFalse([name for name, row in operations.items()
                          if row['matrix_status'] == 'unclassified'])
        self.assertEqual(operations['end']['matrix_status'], 'partially_implemented')
        self.assertEqual(operations['current_state']['category'], 'OVAL element')
        self.assertEqual(self.matrix['operation_coverage_summary'], {
            'intentionally_excluded': 12,
            'native_language_gap': 3,
            'partially_implemented': 351,
        })


if __name__ == '__main__':
    unittest.main()
