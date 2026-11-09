"""Opt-in Issue #28 recovery metadata never changes the default contract."""
from hashlib import sha256
import os
from pathlib import Path
import unittest

from scap_ng_tools.converter.direct04 import convert_benchmark, convert_focused


class RecoveryMetadataContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schema = os.environ.get('SCAP_NG_SCHEMA_ROOT')
        source_dir = os.environ.get('SCAP_NG_ISSUE28_SOURCE_DIR')
        if not schema or not source_dir:
            raise unittest.SkipTest('Issue #28 schema and source fixtures required')
        cls.schema = Path(schema)
        cls.source_dir = Path(source_dir)
        cls.source = cls.source_dir / 'U_MS_Windows_Server_2025_V1R1_STIG_SCAP_1-4_Benchmark-enhancedV1-signed.zip'
        if not cls.source.is_file():
            raise unittest.SkipTest('Issue #28 source fixture is not available')
        cls.pin = sha256(cls.source.read_bytes()).hexdigest()

    def test_default_metadata_is_legacy_golden_shape(self):
        _documents, trace, coverage = convert_benchmark(
            schema_root=self.schema, source=self.source, sha256_pin=self.pin)
        self.assertEqual(trace['scope'],
                         'Automated Assessment/selection subset, not full Rule-policy or Benchmark conversion')
        self.assertNotIn('recovery', coverage)
        self.assertEqual(coverage['scope'],
                         'Automated subset only; not complete Benchmark, manual, applicability or policy equivalence')

    def test_native_recovery_metadata_is_explicit_and_provenance_bound(self):
        _documents, trace, coverage = convert_benchmark(
            schema_root=self.schema, source=self.source, sha256_pin=self.pin,
            native_recovery=True)
        self.assertIn('explicitly recovered manual Assessment subset', trace['scope'])
        self.assertEqual(coverage['recovery'], {
            'native_recovery': True, 'manual_recovery': False,
            'excluded_sqlext': False, 'sqlext_nodes': []})
        # The visitor emits the PR #33 candidate envelope, but the frozen 0.4
        # schema intentionally rejects it until the owner approves the schema
        # contract. This is an explicit hold, not a silently claimed recovery.
        row = next(item for item in coverage['rules']
                   if item['source_rule'] == 'xccdf_mil.disa.stig_rule_SV-278143r1182092_rule')
        self.assertEqual(row['status'], 'blocked')
        self.assertEqual(row['primary_blocker']['category'], 'schema-semantic')
        self.assertIn('substring', row['primary_blocker']['message'])

    def test_manual_recovery_metadata_is_explicit_for_focused_conversion(self):
        # This Rule has both OVAL and OCIL checks in the pinned IE11 source.
        source = self.source_dir / 'U_MS_IE11_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip'
        rule_id = 'xccdf_mil.disa.fso_rule_SV-223017r961089_rule'
        documents, trace = convert_focused(
            schema_root=self.schema, source=source,
            sha256_pin=sha256(source.read_bytes()).hexdigest(), rule_ids=[rule_id],
            native_recovery=True, recover_manual=True)
        rule = next(item['rule'] for path, item in documents.items() if '/rules/' in path)
        self.assertEqual(rule['default_assessment_choice'], 'automated')
        self.assertEqual(set(rule['assessment_choices']), {'automated', 'manual'})
        self.assertIn('explicitly recovered manual Assessment subset', trace['scope'])
