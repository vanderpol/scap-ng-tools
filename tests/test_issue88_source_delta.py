import tempfile
import unittest
from pathlib import Path
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build_issue88_source_delta import build

XML = b'''<oval_definitions><definitions><definition id="def:1"/></definitions><tests><x_test id="tst:1"/></tests></oval_definitions>'''

class SourceDeltaTests(unittest.TestCase):
    def test_delta_tracks_file_and_embedded_identity_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "old" / "SCAP_1.4/OVAL_Test_Content/agnostic"
            new = Path(tmp) / "new" / "SCAP_1.4/OVAL_Test_Content/agnostic"
            old.mkdir(parents=True); new.mkdir(parents=True)
            (old / "one.xml").write_bytes(XML)
            (new / "one.xml").write_bytes(XML.replace(b"def:1", b"def:2"))
            with zipfile.ZipFile(old / "oval-def-ext.zip", "w") as z:
                z.writestr("inner.xml", XML)
            with zipfile.ZipFile(new / "oval-def-ext.zip", "w") as z:
                z.writestr("inner.xml", XML.replace(b"tst:1", b"tst:2"))
            receipt = build(Path(tmp) / "old", Path(tmp) / "new", "old", "new")
            self.assertEqual(receipt["summary"]["changed_files"], 2)
            self.assertIn(("SCAP_1.4/OVAL_Test_Content/agnostic/one.xml", "def:1"),
                          [tuple(x) for x in receipt["summary"]["removed_definition_identities"]])
            self.assertIn(("SCAP_1.4/OVAL_Test_Content/agnostic/oval-def-ext.zip!inner.xml", "tst:1"),
                          [tuple(x) for x in receipt["summary"]["removed_test_identities"]])

if __name__ == "__main__":
    unittest.main()
