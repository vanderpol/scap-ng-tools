"""Exact-head root-cause grouping for the remaining 98 Rule blockers."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / 'docs/evidence/issue59/full65-operation-directed-v2-source-rule-rebuild.json'
GROUPS = ROOT / 'docs/evidence/issue59/blocker-groups-98-v2.json'
OVAL = ROOT / 'docs/evidence/issue59/oval-accounting-operation-directed.json'


class Issue69BlockerGroups(unittest.TestCase):
    def test_grouping_is_complete_and_preserves_exact_rule_id_witnesses(self):
        receipt = json.loads(RECEIPT.read_text())
        groups = json.loads(GROUPS.read_text())
        expected = {
            'canonical-capability-absent': 71,
            'canonical-registry-traversal-gap': 1,
            'source-consumer-datatype-conflict': 1,
            'source-test-state-family-conflict': 7,
            'text-function-non_scalar_or_record_input': 12,
            'unsupported-input-function-composition': 1,
            'unsupported-state-field-namespace': 2,
            'unsupported-variable-cast': 1,
            'variable-source-set-filter-shape': 2,
        }
        self.assertEqual(groups['candidate'], receipt['candidate'])
        self.assertEqual(groups['group_counts'], expected)
        self.assertEqual(groups['total_blocked'], 98)
        self.assertEqual(sum(expected.values()), 98)
        receipt_ids = {(row['benchmark'], row['source_rule'])
                       for row in receipt['blocked_rule_ids']}
        grouped_ids = {(row['benchmark'], row['source_rule'])
                       for group in groups['groups'].values()
                       for row in group['rules']}
        self.assertEqual(grouped_ids, receipt_ids)
        self.assertFalse(groups['qualification']['scanner_equivalent'])
        self.assertFalse(groups['qualification']['runtime_ri_equivalent'])

    def test_standalone_oval_rebuild_keeps_accounting_and_parity_hold(self):
        oval = json.loads(OVAL.read_text())
        self.assertEqual((oval['source_files'], oval['source_definitions'], oval['source_tests']),
                         (144, 168, 803))
        self.assertEqual(oval['candidate']['summary']['converted_definitions'], 97)
        self.assertEqual(oval['candidate']['summary']['converted_tests'], 506)
        self.assertTrue(oval['parity']['source_accounted'])
        self.assertFalse(oval['parity']['complete'])
        self.assertEqual(oval['parity']['problem_types'], {'converted_parity_failure': 55})
        self.assertFalse(oval['parity']['scanner_equivalent'])


if __name__ == '__main__':
    unittest.main()
