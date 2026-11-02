"""Fail if the initial migrated converter engine is silently rewritten."""

from hashlib import sha256
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / 'src/scap_ng_tools/converter/_v04_runtime'
EXPECTED_COPY_SHA256 = '893ca2bef18245d636b662d6d1536bfa1c2aa5643a62ab60d88dad986fb7c46d'
SOURCE_COMMIT = 'd12a644f4607cdc9c9ada50e3a96d4fd0060c6d9'


class DirectConverterSourceCopyTests(unittest.TestCase):
    def test_initial_direct_engine_is_exact_copied_source(self):
        paths = sorted(p for p in RUNTIME.iterdir()
                       if p.suffix in ('.py', '.json') and p.name != '__init__.py')
        self.assertEqual(len(paths), 18)
        digest = sha256()
        for path in paths:
            self.assertFalse(path.is_symlink())
            digest.update(path.name.encode('utf-8') + b'\0')
            digest.update(path.read_bytes())
        self.assertEqual(digest.hexdigest(), EXPECTED_COPY_SHA256)


if __name__ == '__main__':
    unittest.main()
