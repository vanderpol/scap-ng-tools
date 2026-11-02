"""Standalone safety tests for the first copy-first authoring utilities."""
import json
from pathlib import Path
import tempfile
import unittest

from scap_ng_tools.authoring.names import benchmark_folder, native_relative, source_sv
from scap_ng_tools.authoring.records import original_records


class NamingTests(unittest.TestCase):
    def test_reviewed_benchmark_alias(self):
        self.assertEqual(benchmark_folder('Red Hat Enterprise Linux 9 STIG SCAP Benchmark'), 'rhel_9')

    def test_no_implicit_reserved_scope(self):
        with self.assertRaises(ValueError):
            benchmark_folder('shared')

    def test_verified_source_identity_for_names(self):
        self.assertEqual(source_sv({'source_rule': 'org.example.rule.SV-278080'}), 'SV-278080')
        self.assertEqual(native_relative('ms_windows_server_2025', 'assessment', 'SV-278080'),
                         'ms_windows_server_2025/assessments/automated/SV-278080.automated.yaml')
        with self.assertRaises(ValueError):
            native_relative('ms_windows_server_2025', 'assessment', 'unverified-id')
        with self.assertRaises(ValueError):
            source_sv({'source_rule': 'no-sv-id'})


class OriginalRecordTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.authoring = self.base / 'authoring'
        self.authoring.mkdir()
        records = self.base / 'records' / 'streams'
        records.mkdir(parents=True)
        specimen = {
            'source_stream': 'windows_server_2025',
            'source_artifact': 'source.zip',
            'original_ledger': {
                'original_zip': {'file': 'windows_server_2025.zip'},
                'rules': [
                    {'source_rule': 'SV-278080', 'title': 'Prevent lock-screen slideshow',
                     'conversion_status': 'CONVERTED_VERIFIED',
                     'assessment_path': 'assessments/lock_screen.json',
                     'independent_source_proof': 'PASS',
                     'preserved_original_rule': 'rules/SV-278080.xml'},
                    {'source_rule': 'SV-278081', 'title': 'Manual configuration review',
                     'conversion_status': 'MANUAL_OCIL_ONLY_PRESERVED',
                     'preserved_original_rule': 'rules/SV-278081.xml'},
                ],
            },
            'native_path_mapping': [{
                'source_path': 'windows_server_2025/assessments/lock_screen.yaml',
                'kind': 'assessment', 'id': 'lock-screen-assessment',
            }],
        }
        (records / 'ms_windows_server_2025.json').write_text(json.dumps(specimen))

    def test_original_record_is_navigation_only(self):
        matches = original_records(self.authoring, query='SLIDESHOW')
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['original_native_assessment_id'], 'lock-screen-assessment')
        self.assertEqual(matches[0]['source_field'], '/original_ledger/rules/0')
        self.assertFalse(matches[0]['editable_native_document'])
        self.assertEqual(matches[0]['proof_status'], 'PASS')

    def test_manual_record_is_not_synthesized_assessment(self):
        matches = original_records(self.authoring, status='MANUAL_OCIL_ONLY_PRESERVED')
        self.assertEqual(len(matches), 1)
        self.assertIsNone(matches[0]['original_native_assessment_id'])
        self.assertEqual(matches[0]['kind'], 'original-rule-record')

    def test_scope_and_resource_boundaries(self):
        with self.assertRaises(ValueError):
            original_records(self.authoring, scope='../escape')
        with self.assertRaises(ValueError):
            original_records(self.authoring, limit=0)
        self.assertEqual(original_records(self.authoring, scope='nonexistent'), [])


if __name__ == '__main__':
    unittest.main()
