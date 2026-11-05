"""Native 0.4 all_exist lowering tests for Issue #28."""
from hashlib import sha256
import json
import os
from pathlib import Path
import unittest

from scap_ng_tools.converter.direct04 import load_runtime

RECOVERY_REPORT = Path(__file__).resolve().parents[1] / 'docs/evidence/issue28/NATIVE-EXISTENCE-RECOVERY.json'


class NativeExistenceLowering(unittest.TestCase):
    def test_all_65_recovery_delta_has_no_regressions(self):
        report = json.loads(RECOVERY_REPORT.read_text(encoding='utf-8'))
        self.assertEqual(report['candidate']['converted'], 6240)
        self.assertEqual(report['candidate']['blocked'], 2652)
        self.assertEqual(report['delta'], {
            'all_recovered_primary_all_exist': True,
            'recovered': 1716,
            'regressions': 0,
        })
        self.assertEqual(sum(item['recovered'] for item in report['benchmarks'].values()), 1716)

    def test_native_04_existence_mapping_boundaries(self):
        native_items_found = load_runtime().native_items_found
        self.assertEqual(native_items_found('all_exist'), 'one_or_more')
        self.assertEqual(native_items_found('at_least_one_exists'), 'one_or_more')
        self.assertEqual(native_items_found('none_exist'), 'none')
        self.assertEqual(native_items_found('only_one_exists'), 'exactly_one')
        self.assertEqual(native_items_found('any_exist'), 'zero_or_more')
        with self.assertRaisesRegex(ValueError, 'unsupported Test existence'):
            native_items_found('unknown_existence')

    def test_source_backed_rule_emits_native_one_or_more_and_provenance(self):
        source_dir = os.environ.get('SCAP_NG_ISSUE28_SOURCE_DIR')
        schema_root = os.environ.get('SCAP_NG_SCHEMA_ROOT')
        if not source_dir or not schema_root:
            self.skipTest('Issue #28 source and schema fixtures are required')
        source = Path(source_dir) / 'U_Adobe_Acrobat_Pro_DC_Continuous_V2R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip'
        if not source.is_file():
            self.skipTest('Adobe source fixture is not available')
        from scap_ng_tools.converter.direct04 import convert_benchmark
        source_hash = sha256(source.read_bytes()).hexdigest()
        documents, trace, coverage = convert_benchmark(
            schema_root=schema_root, source=source, sha256_pin=source_hash,
            native_recovery=True)
        source_rule = 'xccdf_mil.disa.stig_rule_SV-213126r766535_rule'
        row = next(row for row in coverage['rules'] if row['source_rule'] == source_rule)
        self.assertEqual(row['status'], 'converted')
        binding = next(item for item in trace['rules'] if item['source_rule'] == source_rule)
        controls = binding['source_test_controls']
        self.assertTrue(controls)
        self.assertTrue(all(item['native_items_found'] == 'one_or_more' for item in controls))
        assessment = next(document['assessment'] for path, document in documents.items()
                          if path.endswith('.json') and 'assessments/' in path)
        self.assertTrue(any(test['require']['item_requirement']['items_found'] == 'one_or_more'
                            for test in assessment['tests'].values()))


if __name__ == '__main__':
    unittest.main()
