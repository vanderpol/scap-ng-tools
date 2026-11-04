"""Exact 100-capability offline editor-pack export from the flat 0.4 schema."""

from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from build_v04_editor_metadata_pack import build  # noqa: E402


SCHEMA_COMMIT = 'c0e70f3428ff34abdb6d2daf3fbf14cad84a3e65'
EXPECTED_MANIFEST = '18d1cca6c00b0ee490dd5ae33d0095816a5be29e8f1d47908f1bfa0216b7805f'


class EditorPackParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schema = os.environ.get('SCAP_NG_SCHEMA_ROOT')
        oval = os.environ.get('SCAP_NG_OVAL_ROOT')
        if not schema or not oval:
            raise unittest.SkipTest('Pinned flat schema and official OVAL checkout required')
        cls.schema = Path(schema)
        cls.oval = Path(oval)

    def test_all_236_reviewed_amended_resources_match_explicit_new_pin(self):
        with tempfile.TemporaryDirectory(prefix='scapng-editor-pack-') as temp:
            output = Path(temp) / 'metadata'
            profile = build(self.schema, self.oval, SCHEMA_COMMIT, output)
            self.assertEqual(profile, {
                'schemaVersion': '0.4.0',
                'sourceCommit': SCHEMA_COMMIT,
                'manifestSha256': EXPECTED_MANIFEST,
            })
            self.assertEqual(json.loads((output / 'profile.json').read_bytes()), profile)
            manifest_bytes = (output / 'manifest.json').read_bytes()
            self.assertEqual(sha256(manifest_bytes).hexdigest(), EXPECTED_MANIFEST)
            manifest = json.loads(manifest_bytes)
            self.assertEqual(manifest['source_commit'], SCHEMA_COMMIT)
            self.assertEqual(len(manifest['resources']), 236)
            self.assertEqual(len(manifest['capabilities']), 100)
            names = set()
            for row in manifest['resources']:
                self.assertNotIn(row['path'], names)
                names.add(row['path'])
                self.assertEqual(sha256((output / row['path']).read_bytes()).hexdigest(),
                                 row['sha256'])
                self.assertEqual((output / row['path']).stat().st_size, row['bytes'])
            self.assertEqual(len(names), 236)
            self.assertEqual(
                {p.relative_to(output).as_posix() for p in output.rglob('*') if p.is_file()},
                names | {'profile.json', 'manifest.json'})

    def test_wrong_schema_commit_and_preexisting_output_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix='scapng-editor-pack-negative-') as temp:
            output = Path(temp) / 'metadata'
            with self.assertRaisesRegex(ValueError, 'sourceCommit'):
                build(self.schema, self.oval, '0' * 40, output)
            self.assertFalse(output.exists())
            output.mkdir()
            with self.assertRaisesRegex(ValueError, 'overwrite'):
                build(self.schema, self.oval, SCHEMA_COMMIT, output)


if __name__ == '__main__':
    unittest.main()
