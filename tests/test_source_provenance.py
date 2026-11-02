"""Fail closed if an exact copied source module is edited without review."""
from hashlib import sha256
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    'names.py': '49773328435e486ca46d09e8a694f17d29b00d61e05cf2ab376b1604eefcdbe5',
    'records.py': 'a715f8358001f996801af67ea57e2f149ef32596da98fe509517b524e508d965',
}


class SourceProvenanceTests(unittest.TestCase):
    def test_copied_0_4_helpers_are_byte_identical(self):
        for name, expected in EXPECTED.items():
            with self.subTest(module=name):
                actual = sha256((ROOT/'src/scap_ng_tools/authoring'/name).read_bytes()).hexdigest()
                self.assertEqual(actual, expected, 'review provenance and change tests before editing source')


if __name__ == '__main__':
    unittest.main()
