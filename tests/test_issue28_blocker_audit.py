"""Pinned aggregate evidence for the Issue #28 all-65 triage packet."""
import json
from pathlib import Path
import unittest


REPORT = Path(__file__).resolve().parents[1] / 'docs/evidence/issue28/BLOCKER-AUDIT.json'


class Issue28BlockerAudit(unittest.TestCase):
    def test_generated_schema_diagnostics_group_by_root_cause(self):
        import sys
        sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
        from audit_issue28_blockers import issue_key
        self.assertEqual(issue_key({'category': 'schema-semantic',
                                    'message': "foo: {'function': {'name': 'count'}} is not valid under any of the given schemas"}),
                         ('schema-semantic', 'native function contract admission: count'))
        self.assertEqual(issue_key({'category': 'schema-semantic',
                                    'message': 'foo: Native Variable expression: declared/derived datatype conflict'}),
                         ('schema-semantic', 'native Variable declared/derived datatype mismatch'))
        self.assertEqual(issue_key({'category': 'schema-semantic',
                                    'message': "foo: {'traversal': {'max_depth': 1}} is not valid under any of the given schemas"}),
                         ('schema-semantic', 'native traversal contract admission'))

    def test_primary_root_is_stable_when_validator_error_order_changes(self):
        import sys
        sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
        from audit_issue28_blockers import primary_blocker
        count = {'category': 'schema-semantic',
                 'message': "foo: {'function': {'name': 'count'}} is not valid under any of the given schemas"}
        split = {'category': 'schema-semantic',
                 'message': "foo: {'function': {'name': 'split'}} is not valid under any of the given schemas"}
        self.assertEqual(primary_blocker([split, count]), count)
        self.assertEqual(primary_blocker([count, split]), count)

        access = {'category': 'unsupported-capability', 'message': 'access'}
        wmi = {'category': 'unsupported-capability', 'message': 'wmi'}
        self.assertEqual(primary_blocker([access, wmi]), access)
        self.assertEqual(primary_blocker([wmi, access]), wmi)

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
