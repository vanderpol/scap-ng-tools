"""Current full-65 source identity/nonregression receipt."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Full65CurrentReceipt(unittest.TestCase):
    def test_current_main_ledger_is_source_pinned_and_nonregressing(self):
        r = json.loads((ROOT / 'docs/evidence/issue85/full65-current-20261122-main.json').read_text())
        self.assertEqual(r['converter']['commit'], '0b7c0ba99dfc659d7da17e41a31dd954a3e2aaf0')
        self.assertEqual(r['canonical']['commit'], 'f51ab2c5bd82c94a9c292a7abb2ef1a7edc91ca2')
        self.assertEqual(r['source']['benchmarks'], 65)
        self.assertEqual(r['source']['owner_scope']['active'], 7990)
        self.assertEqual(r['baseline'], {'blocked': 108, 'converted': 6479, 'manual_only': 1403})
        self.assertEqual(r['candidate'], {'blocked': 94, 'converted': 6493, 'manual_only': 1403})
        self.assertEqual(r['transitions']['newly_converted_from_blocked'], 14)
        self.assertEqual(r['transitions']['newly_blocked_from_converted'], 0)
        self.assertTrue(r['transitions']['nonregression_pass'])
        self.assertEqual(len(r['recovered_rule_ids']), 14)
        self.assertEqual(r['raw_blocker_categories'], {
            'schema-semantic': 12, 'unsupported-capability': 80,
            'unsupported-construct': 2})
        self.assertFalse(r['qualification'].endswith('equivalence proved'))
