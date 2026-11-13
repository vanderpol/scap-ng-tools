"""Committed Issue #59 qualification receipts for the one active 0.4.1 pack."""
import json
from pathlib import Path
import unittest

from scap_ng_tools.converter._v04_semantic import PACK_HASH, SCHEMA_HASH, contracts

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'docs/evidence/issue59'


class Issue59QualificationReceipts(unittest.TestCase):
    def test_pack_identity_and_full65_receipt(self):
        pack = contracts()
        self.assertEqual(pack['schema_version'], '0.4.1')
        self.assertEqual(pack['frozen_schema_digest'], SCHEMA_HASH)
        self.assertEqual(len(pack['capabilities']), 52)
        full = json.loads((EVIDENCE / 'full65-conversion-v041.json').read_text())
        self.assertEqual(len(full['benchmarks']), 65)
        totals = {'source': 0, 'converted': 0, 'blocked': 0, 'manual_only': 0}
        for row in full['benchmarks']:
            totals['source'] += row['source_rules']
            for key in ('converted', 'blocked', 'manual_only'):
                totals[key] += row['summary']['statuses'].get(key, 0)
        self.assertEqual(totals, {
            'source': 8892, 'converted': 6732, 'blocked': 507, 'manual_only': 1653})

    def test_crosswalk_is_same_source_scope_and_oval_ledger_is_complete(self):
        crosswalk = json.loads((EVIDENCE / 'full65-crosswalk.json').read_text())
        self.assertEqual(crosswalk['summary']['benchmarks'], 65)
        self.assertEqual(crosswalk['summary']['source_rules'], 8892)
        self.assertEqual(crosswalk['summary']['delta'], {
            'converted': -196, 'blocked': 333, 'manual_only': 72})
        oval = json.loads((EVIDENCE / 'oval-accounting.json').read_text())
        self.assertEqual((oval['source_files'], oval['source_definitions'], oval['source_tests']),
                         (144, 168, 803))
        self.assertEqual(oval['results']['converted_definitions'], 92)
        self.assertEqual(oval['results']['converted_tests'], 478)
        self.assertTrue(oval['transitive_extend_definition_ownership'])
        self.assertFalse(oval['qualification']['scanner_equivalent'])


if __name__ == '__main__':
    unittest.main()
