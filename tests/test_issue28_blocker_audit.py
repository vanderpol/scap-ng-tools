"""Pinned aggregate evidence for the Issue #28 all-65 triage packet."""
import json
from pathlib import Path
import unittest


REPORT = Path(__file__).resolve().parents[1] / 'docs/evidence/issue28/BLOCKER-AUDIT.json'


class Issue28BlockerAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(REPORT.read_text(encoding='utf-8'))

    def test_owner_baseline_is_complete_and_accounted(self):
        report = self.report
        self.assertEqual(report['scope']['benchmarks'], 65)
        self.assertEqual(report['scope']['rules'], 8892)
        self.assertEqual(report['baseline'], {'blocked': 4368, 'converted': 4524, 'total': 8892})
        self.assertEqual(len(report['benchmarks']), 65)
        self.assertEqual(sum(row['source_rules'] for row in report['benchmarks']), 8892)
        self.assertEqual(sum(row['converted'] for row in report['benchmarks']), 4524)
        self.assertEqual(sum(row['blocked'] for row in report['benchmarks']), 4368)

    def test_primary_diagnostics_are_mutually_exclusive(self):
        self.assertEqual(sum(row['rules'] for row in self.report['primary_blockers']), 4368)
        self.assertEqual(self.report['primary_blockers'][0]['rules'], 1750)
        self.assertIn('all_exist', self.report['primary_blockers'][0]['message'])
        self.assertEqual(self.report['primary_blockers'][1]['rules'], 1653)

    def test_variable_function_inventory_is_explicit(self):
        usage = self.report['variable_function_usage']
        for name in ('external_variable', 'local_variable', 'constant_variable',
                     'concat', 'regex_capture', 'unique', 'merge', 'count',
                     'split', 'substring'):
            self.assertIn(name, usage)
            self.assertEqual(usage[name]['total'], usage[name]['converted'] + usage[name]['blocked'])
        self.assertEqual(usage['concat']['total'], 299)
        self.assertEqual(usage['count']['blocked'], 37)
        self.assertEqual(usage['external_variable']['blocked'], 426)


if __name__ == '__main__':
    unittest.main()
