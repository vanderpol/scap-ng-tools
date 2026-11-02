"""Offline schema resolver contract, including a deliberate stale-byte failure."""

from hashlib import sha256
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from scap_ng_tools.contracts import FrozenSchemaSnapshot, SnapshotError
from scap_ng_tools.contracts.schema_snapshot import FROZEN_DIGEST, fingerprint


class SchemaSnapshotTests(unittest.TestCase):
    def test_fingerprint_includes_relative_paths_and_exact_bytes(self):
        with tempfile.TemporaryDirectory(prefix='scapng-snapshot-hash-') as temp:
            root = Path(temp)
            first, second = root / 'a.json', root / 'b.json'
            first.write_bytes(b'{"x":1}\n')
            second.write_bytes(b'{"x":2}\n')
            expected = sha256(b'a.json\0{"x":1}\nb.json\0{"x":2}\n').hexdigest()
            self.assertEqual(fingerprint([second, first], root), expected)
            second.write_bytes(b'{"x":2} ')
            self.assertNotEqual(fingerprint([first, second], root), expected)

    def test_missing_or_legacy_layout_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix='scapng-snapshot-empty-') as temp:
            root = Path(temp)
            with self.assertRaises(SnapshotError):
                FrozenSchemaSnapshot(root)
            (root / 'schema' / 'v0.4.0').mkdir(parents=True)
            with self.assertRaises(SnapshotError):
                FrozenSchemaSnapshot(root)

    def test_external_pinned_flat_snapshot_and_tamper(self):
        root = os.environ.get('SCAP_NG_SCHEMA_ROOT')
        if not root:
            self.skipTest('Pass SCAP_NG_SCHEMA_ROOT to test a real flat snapshot')
        snapshot = FrozenSchemaSnapshot(root)
        self.assertEqual(snapshot.manifest()['aggregate_sha256'], FROZEN_DIGEST)
        self.assertEqual(len(snapshot.supported_mappings()), 100)
        self.assertEqual(snapshot.supported_mapping('windows.registry')['capability'],
                         'windows.registry')
        with self.assertRaises(SnapshotError):
            snapshot.supported_mapping('../windows.registry')
        with self.assertRaises(SnapshotError):
            snapshot.supported_mapping('not.a.capability')

        with tempfile.TemporaryDirectory(prefix='scapng-snapshot-tamper-') as temp:
            destination = Path(temp) / 'schema'
            shutil.copytree(snapshot.schema_root, destination)
            data = destination / 'assessment.schema.json'
            data.write_bytes(data.read_bytes() + b' ')
            with self.assertRaisesRegex(SnapshotError, 'digest mismatch'):
                FrozenSchemaSnapshot(destination)


if __name__ == '__main__':
    unittest.main()
