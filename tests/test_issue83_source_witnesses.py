"""Focused safety tests for the bounded OVAL source witness harness."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

try:
    from lxml import etree
except ImportError:  # pragma: no cover - environment gated
    etree = None

import build_issue83_source_witnesses as witnesses  # noqa: E402


@unittest.skipUnless(etree is not None, "lxml witness validator is environment-gated")
class Issue83SourceWitnessTests(unittest.TestCase):
    def test_reference_extraction_includes_nested_refs_and_filters(self):
        node = etree.fromstring(
            '<test xmlns="urn:test"><object object_ref="obj-1"/>'
            '<state state_ref="state-1"/><filter>state-2</filter>'
            '<value var_ref="var-1"/></test>')
        self.assertEqual(list(witnesses.WitnessBuilder._refs(node)), [
            ("object", "obj-1"), ("state", "state-1"),
            ("variable", "var-1"), ("state", "state-2")])

    def test_local_ignores_comments(self):
        comment = etree.Comment("comment")
        self.assertEqual(witnesses.local(comment.tag), "")
        self.assertEqual(witnesses.local("{urn:test}field"), "field")


if __name__ == "__main__":
    unittest.main()
