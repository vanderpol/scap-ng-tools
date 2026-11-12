"""Candidate active-scope ledger reconciliation and function recovery counts."""
import gzip
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / 'docs/evidence/issue28/ACTIVE-CANDIDATE-LEDGER.json'
RULES = ROOT / 'docs/evidence/issue28/ACTIVE-CANDIDATE-RULES.json.gz'
RECOVERY = ROOT / 'docs/evidence/issue28/RECOVERY-RESULTS.json'

class ActiveCandidateLedger(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ledger = json.loads(LEDGER.read_text())
        cls.recovery = json.loads(RECOVERY.read_text())
        with gzip.open(RULES, 'rt', encoding='utf-8') as stream:
            cls.records = json.load(stream)

    def test_active_classification_is_mutually_exclusive_and_reconciles(self):
        classification = self.ledger['classification']
        self.assertEqual(sum(classification.values()), 8199)
        self.assertEqual(classification, {
            'automated_converted_proved': 0,
            'automated_converted_unproved': 6479,
            'manual_only': 1403,
            'genuinely_blocked': 108,
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

    def test_wmi_and_xccdf_recovery_counts_are_separate_from_function_counts(self):
        self.assertEqual(self.ledger['recovery_targets']['legacy_wmi'],
                         {'historical_blockers': 15, 'migration_candidates': 15,
                          'recovered': 1, 'remaining': 14})
        self.assertEqual(self.ledger['recovery_targets']['xccdf_value_constraints'],
                         {'historical_blockers': 5, 'recovered': 5, 'remaining': 0})
        self.assertEqual(self.ledger['recovered_blocker_rules'], 6)

    def test_recovery_results_reconcile_source_rule_transitions(self):
        self.assertEqual(len(self.recovery['status_transitions']), 6)
        self.assertEqual(self.recovery['legacy_wmi']['fully_recovered'], 1)
        self.assertEqual(self.recovery['legacy_wmi']['remaining_downstream_blockers'], 14)
        self.assertEqual(self.recovery['xccdf_value_constraints']['recovered'], 5)
        self.assertFalse(self.recovery['qualification']['independently_proved'])

    def test_candidate_pin_and_no_proof_claim(self):
        self.assertEqual(self.ledger['scope']['schema_commit'], '919732d4c570b521edf82196a7694dfd8c27fe50')
        self.assertEqual(self.ledger['scope']['schema_family_sha256'],
                         '6bf2fa369fd7b9a0153899ac25109af3e3f9aa59c0f4aa6bb3be1aebd5b14fa0')
        self.assertFalse(self.ledger['provenance']['independent_proof_claim'])
        self.assertFalse(self.ledger['provenance']['compiler_scanner_equivalence_claim'])

if __name__ == '__main__':
    unittest.main()

class FinalBlockerMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = json.loads((ROOT / 'docs/evidence/issue28/FINAL-BLOCKER-MATRIX.json').read_text())

    def test_every_active_blocker_has_one_stable_review_root(self):
        self.assertEqual(self.matrix['qualification']['individual_rule_rows'], 108)
        self.assertEqual(len(self.matrix['rules']), 108)
        self.assertEqual(sum(self.matrix['counts_by_root_cause'].values()), 108)
        self.assertEqual(self.matrix['counts_by_root_cause']['legacy_wmi_record_projection'], 14)
        self.assertEqual(self.matrix['counts_by_root_cause']['deprecated_accesstoken'], 66)
        self.assertFalse(self.matrix['qualification']['independent_proof_claim'])
