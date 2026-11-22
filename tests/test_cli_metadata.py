"""Portable converter CLI identity smoke tests (no schema/source required)."""
import json
from pathlib import Path
import subprocess
import sys
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ConverterCliMetadata(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, '-m', 'scap_ng_tools.converter.direct04', *args],
            cwd=ROOT, capture_output=True, text=True)

    def test_version_is_portable_and_reports_exact_contract_identity(self):
        result = self.run_cli('--version')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        payload = json.loads(result.stdout)
        self.assertEqual(payload['package'], 'scap-ng-tools')
        self.assertEqual(payload['converter_interface'], 'scap-ng-convert-v04/1')
        self.assertEqual(payload['schema_version'], '0.4.1')
        for field in ('canonical_commit', 'oval_schema_commit',
                      'flat_schema_family_sha256',
                      'assessment_execution_family_sha256',
                      'assessment_closure_sha256', 'semantic_pack_sha256'):
            self.assertRegex(payload[field], r'^[0-9a-f]{40,64}$')
        self.assertIn('required for conversion', payload['offline_schema_argument'])

    def test_project_metadata_is_buildable_under_current_pep621_rules(self):
        project = tomllib.loads((ROOT / 'pyproject.toml').read_text())['project']
        self.assertEqual(project['license'], {'text': 'Apache-2.0'})
        self.assertEqual(project['requires-python'], '>=3.11')

    def test_conversion_arguments_remain_required_without_version(self):
        result = self.run_cli()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('--schema-root is required unless --version is used', result.stderr)
