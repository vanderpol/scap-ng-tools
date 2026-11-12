"""Keep the Issue #28 qualification audit synchronized with evidence artifacts."""
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class Issue28CompletionAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit = (ROOT / 'docs/evidence/issue28/COMPLETION-AUDIT.md').read_text()
        cls.ledger = json.loads((ROOT / 'docs/evidence/issue28/COMPLETE-LEDGER.json').read_text())
        cls.inventory = json.loads((ROOT / 'docs/evidence/issue28/OVAL-SOURCE-INVENTORY.json').read_text())

    def test_audit_keeps_the_complete_ledger_counts_visible(self):
        counts = self.ledger['classification']
        self.assertEqual(self.ledger['scope']['benchmarks'], 65)
        self.assertEqual(self.ledger['scope']['rules'], 8892)
        self.assertEqual(self.inventory['source_count'], 65)
        self.assertEqual(self.inventory['rule_count'], 8892)
        self.assertEqual(len(self.inventory['operations']), 366)
        for count in (counts['automated_converted_unproved'], counts['manual_only'],
                      counts['genuinely_blocked'], counts['intentionally_excluded']):
            self.assertIn(f'{count:,}', self.audit)
        self.assertIn('0 proved', self.audit)

    def test_audit_does_not_promote_unproved_scanner_semantics(self):
        self.assertIn('Not achieved; no Rule is promoted to proved', self.audit)
        self.assertIn('compiler/scanner execution', self.audit)
        self.assertEqual(self.ledger['classification']['automated_converted_proved'], 0)


if __name__ == '__main__':
    unittest.main()
