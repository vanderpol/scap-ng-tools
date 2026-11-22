"""Build-time offline bundle manifest and integrity checks for Tools #86."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class OfflineBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        value = os.environ.get('SCAP_NG_SCHEMA_ROOT')
        if not value:
            raise unittest.SkipTest('Set SCAP_NG_SCHEMA_ROOT to the exact pinned flat 0.4.1 schema')
        cls.schema = Path(value)

    def test_stages_exact_schema_and_converter_with_negative_integrity_check(self):
        with tempfile.TemporaryDirectory(prefix='scapng-offline-bundle-') as temp:
            bundle = Path(temp) / 'bundle'
            result = subprocess.run([
                sys.executable, 'scripts/build_offline_bundle.py',
                '--schema-root', str(self.schema), '--output', str(bundle),
            ], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((bundle / 'manifest.json').read_text())
            self.assertEqual(manifest['format'], 'scap-ng-tools/offline-bundle/1')
            self.assertFalse(manifest['self_contained_runtime'])
            self.assertEqual(manifest['schema']['flat_schema_family_sha256'],
                             '1755c893712ef30334dc7ecadc88e5abf387c2d60a75211bc2445b7cefa2e7d4')
            self.assertTrue((bundle / manifest['entrypoint']).is_file())
            verify = subprocess.run([
                sys.executable, 'scripts/build_offline_bundle.py',
                '--verify', str(bundle),
            ], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(verify.returncode, 0, verify.stderr)
            launcher = subprocess.run([str(bundle / manifest['entrypoint']), '--version'],
                                      cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(launcher.returncode, 0, launcher.stderr)
            self.assertEqual(json.loads(launcher.stdout)['schema_version'], '0.4.1')
            missing_env = os.environ.copy()
            missing_env['PYTHON'] = '/bin/false'
            missing_deps = subprocess.run([str(bundle / manifest['entrypoint']), '--source', 'missing.xml'],
                                          cwd=ROOT, env=missing_env,
                                          capture_output=True, text=True)
            self.assertEqual(missing_deps.returncode, 78)
            self.assertIn('SCAP_NG_OFFLINE_BUNDLE_DEPENDENCY_ERROR', missing_deps.stderr)
            (bundle / 'schema' / 'assessment.schema.json').write_bytes(
                (bundle / 'schema' / 'assessment.schema.json').read_bytes() + b'\n')
            tampered = subprocess.run([
                sys.executable, 'scripts/build_offline_bundle.py',
                '--verify', str(bundle),
            ], cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(tampered.returncode, 0)
            self.assertIn('schema tree digest mismatch', tampered.stderr)
