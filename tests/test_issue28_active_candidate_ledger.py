"""Candidate active-scope ledger reconciliation and function recovery counts."""
import gzip
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / 'docs/evidence/issue28/ACTIVE-CANDIDATE-LEDGER.json'
RULES = ROOT / 'docs/evidence/issue28/ACTIVE-CANDIDATE-RULES.json.gz'

class ActiveCandidateLedger(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ledger = json.loads(LEDGER.read_text())
        with gzip.open(RULES, 'rt', encoding='utf-8') as stream:
            cls.records = json.load(stream)

    def test_active_classification_is_mutually_exclusive_and_reconciles(self):
        classification = self.ledger['classification']
        self.assertEqual(sum(classification.values()), 8199)
        self.assertEqual(classification, {
            'automated_converted_proved': 0,
            'automated_converted_unproved': 6473,
            'manual_only': 1403,
            'genuinely_blocked': 114,
            'intentionally_excluded': 209,
        })
        statuses = {r['status'] for r in self.records['rules']}
        self.assertEqual(len(self.records['rules']), 8199)
        self.assertTrue({'converted', 'manual_only', 'blocked'} <= statuses)

    def test_function_recovery_counts_are_actual_rule_counts(self):
        recovery = self.ledger['per_function_recovery']
        self.assertEqual(sum(v['historical_blockers'] for v in recovery.values()), 90)
        self.assertEqual(sum(v['recovered'] for v in recovery.values()), 82)
        self.assertEqual(sum(v['remaining'] for v in recovery.values()), 8)
        self.assertEqual(recovery['count'], {'historical_blockers': 37, 'recovered': 36, 'remaining': 1})
        self.assertEqual(recovery['multi_component_aggregation'],
                         {'historical_blockers': 30, 'recovered': 30, 'remaining': 0})

    def test_candidate_pin_and_no_proof_claim(self):
        self.assertEqual(self.ledger['scope']['schema_commit'], 'a036357')
        self.assertEqual(self.ledger['scope']['schema_family_sha256'],
                         '094cc95219a0fad3640c5fda366b8ff865eb73e255013d92f46edd24cb579c6b')
        self.assertFalse(self.ledger['provenance']['independent_proof_claim'])
        self.assertFalse(self.ledger['provenance']['compiler_scanner_equivalence_claim'])

if __name__ == '__main__':
    unittest.main()
