"""Fail if the pinned runtime or explicit inventory-path adaptation drifts."""

from hashlib import sha256
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / 'src/scap_ng_tools/converter/_v04_runtime'
INITIAL_SOURCE_COPY_SHA256 = '893ca2bef18245d636b662d6d1536bfa1c2aa5643a62ab60d88dad986fb7c46d'
CURRENT_RUNTIME_SHA256 = 'fcfa3ef00a083dc6510a8e1bd421b338d4c892fde59ab61d693ed60d957bc099'
UNCHANGED_SOURCE_SHA256 = '9b8cd16d4407706ad22d3f604d0cef6c9173fd31a67e4ecb968fdb1a4f71f282'
AUDITED_ADAPTATIONS = {
    'v04_direct_converter.py': 'c373673c4116357027fa1b5fe1f312b156379e6533fb5fbee407843910cb72df',
    'v04_direct_inventory.py': '99a324754b739a9b51d0ae62abed76f8a14d5a172b54ff65beec6fd7ff58d904',
}
SOURCE_COMMIT = 'd12a644f4607cdc9c9ada50e3a96d4fd0060c6d9'


class DirectConverterSourceCopyTests(unittest.TestCase):
    def test_runtime_matches_allowlisted_inventory_path_adaptation(self):
        paths = sorted(p for p in RUNTIME.iterdir()
                       if p.suffix in ('.py', '.json') and p.name != '__init__.py')
        self.assertEqual(len(paths), 18)
        digest = sha256()
        unchanged = sha256()
        for path in paths:
            self.assertFalse(path.is_symlink())
            digest.update(path.name.encode('utf-8') + b'\0')
            digest.update(path.read_bytes())
            if path.name in AUDITED_ADAPTATIONS:
                self.assertEqual(sha256(path.read_bytes()).hexdigest(),
                                 AUDITED_ADAPTATIONS[path.name])
            else:
                unchanged.update(path.name.encode('utf-8') + b'\0')
                unchanged.update(path.read_bytes())
        self.assertEqual(digest.hexdigest(), CURRENT_RUNTIME_SHA256)
        self.assertEqual(unchanged.hexdigest(), UNCHANGED_SOURCE_SHA256)


if __name__ == '__main__':
    unittest.main()
