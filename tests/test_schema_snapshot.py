"""Offline canonical 0.4.1 schema resolver contract and stale-byte failures."""

import os
from pathlib import Path
import shutil
import tempfile
import unittest

from scap_ng_tools.contracts.schema_snapshot_v041 import (
    FLAT_SCHEMA_SHA256, Pinned041SchemaSnapshot, SnapshotError, fingerprint,
)


class SchemaSnapshotTests(unittest.TestCase):
    def test_fingerprint_includes_relative_paths_and_exact_bytes(self):
        with tempfile.TemporaryDirectory(prefix='scapng-snapshot-hash-') as temp:
            root = Path(temp)
            first, second = root / 'a.json', root / 'b.json'
            first.write_bytes(b'{"x":1}\n')
            second.write_bytes(b'{"x":2}\n')
            expected = fingerprint([second, first], root)
            self.assertEqual(fingerprint([first, second], root), expected)
            second.write_bytes(b'{"x":2} ')
            self.assertNotEqual(fingerprint([first, second], root), expected)

    def test_missing_or_parallel_layout_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix='scapng-snapshot-empty-') as temp:
            root = Path(temp)
            with self.assertRaises(SnapshotError):
                Pinned041SchemaSnapshot(root)
            (root / 'schema' / 'v0.4.0').mkdir(parents=True)
            with self.assertRaises(SnapshotError):
                Pinned041SchemaSnapshot(root)

    def test_external_pinned_flat_snapshot_and_tamper(self):
        root = os.environ.get('SCAP_NG_SCHEMA_ROOT')
        if not root:
            self.skipTest('Pass SCAP_NG_SCHEMA_ROOT to test a real flat snapshot')
        snapshot = Pinned041SchemaSnapshot(root)
        self.assertEqual(snapshot.manifest()['aggregate_sha256'], FLAT_SCHEMA_SHA256)
        self.assertEqual(snapshot.manifest()['schema_version'], '0.4.1')
        self.assertEqual(len(snapshot.supported_mappings()), 100)
        self.assertEqual(snapshot.supported_mapping('windows.registry')['capability'], 'windows.registry')
        with self.assertRaises(SnapshotError):
            snapshot.supported_mapping('../windows.registry')
        with self.assertRaises(SnapshotError):
            snapshot.supported_mapping('not.a.capability')

        with tempfile.TemporaryDirectory(prefix='scapng-snapshot-tamper-') as temp:
            destination = Path(temp) / 'schema'
            shutil.copytree(snapshot.schema_root, destination)
            data = destination / 'assessment.schema.json'
            data.write_bytes(data.read_bytes() + b' ')
            with self.assertRaisesRegex(SnapshotError, 'exact approved 0.4.1 digest'):
                Pinned041SchemaSnapshot(destination)


if __name__ == '__main__':
    unittest.main()
