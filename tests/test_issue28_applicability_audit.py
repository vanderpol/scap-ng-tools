import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / 'docs/evidence/issue28/APPLICABILITY-COVERAGE-AUDIT.json'

class ApplicabilityCoverageAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.report = json.loads(REPORT.read_text())
    def test_audit_is_pinned_and_archive_is_preserved(self):
        self.assertEqual(self.report['pins']['source_commit'], '8c8e5dff860af6b1290ee9273a282db24278f8d5')
        self.assertEqual(self.report['pins']['schema_commit'], '919732d4c570b521edf82196a7694dfd8c27fe50')
        self.assertTrue(self.report['interpretation']['preserve_archive'])
    def test_source_and_native_applicability_counts(self):
        s = self.report['summary']
        self.assertEqual(s['source_benchmarks'], 63)
        self.assertEqual(s['source_rules'], 8199)
        self.assertEqual(s['source_rules_with_effective_platform'], 8199)
        self.assertEqual(s['source_platform_fact_refs'], 185)
        self.assertEqual(s['source_platform_fact_refs_resolved'], 185)
        self.assertEqual(s['source_platform_fact_closures_supported'], 183)
        self.assertEqual(s['source_platform_fact_closures_sqlext'], 2)
        self.assertEqual(s['native_catalogs_present'], 59)
        self.assertEqual(s['native_catalogs_nonempty'], 0)
        self.assertEqual(s['native_rules_with_applicability'], 0)
    def test_finding_is_pipeline_limit_not_schema_change(self):
        i = self.report['interpretation']
        self.assertEqual(i['finding'], 'intentional_conversion_pipeline_limitation')
        self.assertFalse(i['schema_gap'])
        self.assertFalse(i['source_mapping_gap'])

if __name__ == '__main__': unittest.main()
