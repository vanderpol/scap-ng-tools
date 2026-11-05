"""Reconciliation checks for the regenerated Issue #28 ledger."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / 'docs/evidence/issue28/COMPLETE-LEDGER.json'
INVENTORY = ROOT / 'docs/evidence/issue28/OVAL-SOURCE-INVENTORY.json'


class Issue28CompleteLedger(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ledger = json.loads(LEDGER.read_text())
        cls.inventory = json.loads(INVENTORY.read_text())

    def test_mutually_exclusive_reconciliation(self):
        self.assertEqual(self.ledger['scope']['benchmarks'], 65)
        self.assertEqual(self.ledger['scope']['rules'], 8892)
        self.assertEqual(self.ledger['baseline']['total'], 8892)
        classification = self.ledger['classification']
        self.assertEqual(sum(classification[key] for key in (
            'automated_converted_proved', 'automated_converted_unproved',
            'manual_only', 'genuinely_blocked', 'intentionally_excluded')), 8892)
        self.assertEqual(classification['automated_converted_proved'], 0)
        self.assertEqual(classification['automated_converted_unproved'], 6524)
        self.assertEqual(classification['manual_only'], 1581)
        self.assertEqual(classification['genuinely_blocked'], 578)
        self.assertEqual(classification['intentionally_excluded'], 209)

    def test_source_inventory_matches_owner_baseline(self):
        self.assertEqual(self.inventory['source_count'], 65)
        self.assertEqual(self.inventory['rule_count'], 8892)
        names = {row['name'] for row in self.inventory['operations']}
        self.assertTrue({'count', 'split', 'substring', 'concat', 'regex_capture',
                         'unique', 'merge', 'arithmetic', 'external_variable'} <= names)


if __name__ == '__main__':
    unittest.main()
