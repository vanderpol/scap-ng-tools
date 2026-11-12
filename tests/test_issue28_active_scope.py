"""Owner-directed active-scope exclusion, retaining the historical ledger."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ActiveScopeExclusion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit = json.loads((ROOT / 'docs/evidence/issue28/ACTIVE-SCOPE-2012-EXCLUSION.json').read_text())

    def test_historical_inventory_is_retained_and_active_scope_reconciles(self):
        audit = self.audit
        self.assertEqual(audit['historical']['rules'], 8892)
        excluded = audit['excluded_active_scope']
        active = audit['active_scope']
        self.assertEqual(excluded['benchmark_count'], 2)
        self.assertEqual(excluded['rules'], 693)
        self.assertEqual(active['benchmarks'], 63)
        self.assertEqual(active['rules'] + excluded['rules'], audit['historical']['rules'])
        for key in ('automated_converted_unproved', 'manual_only', 'genuinely_blocked'):
            self.assertEqual(active['classification'][key] + excluded['classification'][key],
                             audit['historical']['classification'][key])

    def test_access_token_primary_and_source_counts_are_not_conflated(self):
        access = self.audit['active_scope']['accesstoken']
        self.assertEqual(access['historical_primary_blockers'], 125)
        self.assertEqual(access['excluded_primary_blockers'], 61)
        self.assertEqual(access['remaining_primary_blockers'], 64)
        self.assertEqual(access['historical_source_rules'], 127)
        self.assertEqual(access['remaining_source_rules'], 66)
        self.assertEqual(access['remaining_supported_platforms'], ['Windows 10', 'Windows Server 2016'])

    def test_only_the_two_owner_excluded_benchmarks_are_out_of_active_scope(self):
        names = [row['filename'] for row in self.audit['excluded_active_scope']['benchmarks']]
        self.assertEqual(len(names), 2)
        self.assertTrue(all('Windows_2012_and_2012_R2' in name for name in names))


if __name__ == '__main__':
    unittest.main()
