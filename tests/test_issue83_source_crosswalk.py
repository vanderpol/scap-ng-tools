"""Focused source-fidelity tests for Issue #83's reusable crosswalk."""
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_issue83_source_crosswalk as crosswalk  # noqa: E402


class Issue83SourceCrosswalkTests(unittest.TestCase):
    def make_archive(self, directory: Path, *, requires="", conflicts="") -> Path:
        rule = f'''<xccdf:Rule xmlns:xccdf="{crosswalk.XCCDF}" id="xccdf:test_rule" requires="{requires}" conflicts="{conflicts}">
          <xccdf:title>Relationship witness</xccdf:title>
          <xccdf:description>&lt;VulnDiscussion&gt;Keep this discussion&lt;/VulnDiscussion&gt;&lt;FalsePositives&gt;&lt;/FalsePositives&gt;&lt;Documentable&gt;false&lt;/Documentable&gt;</xccdf:description>
        </xccdf:Rule>'''
        xml = f'''<ds:data-stream-collection xmlns:ds="{crosswalk.DS}" xmlns:xccdf="{crosswalk.XCCDF}" id="collection">
          <ds:component id="checklist"><xccdf:Benchmark id="benchmark" xccdf-version="1.2"><xccdf:Rule id="xccdf:test_rule" requires="{requires}" conflicts="{conflicts}">
            <xccdf:title>Relationship witness</xccdf:title>
            <xccdf:description>&lt;VulnDiscussion&gt;Keep this discussion&lt;/VulnDiscussion&gt;&lt;FalsePositives&gt;&lt;/FalsePositives&gt;&lt;Documentable&gt;false&lt;/Documentable&gt;</xccdf:description>
          </xccdf:Rule></xccdf:Benchmark></ds:component>
          <ds:data-stream id="stream" scap-version="1.4"><ds:checklists><ds:component-ref id="checklist" href="#checklist"/></ds:checklists></ds:data-stream>
        </ds:data-stream-collection>'''.encode()
        path = directory / "witness.zip"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("witness.xml", xml)
        return path

    def test_relationships_and_disa_fields_are_source_traced(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self.make_archive(Path(temporary), requires="rule_a rule_b", conflicts="rule_c")
            record = crosswalk.archive_record(path)
        self.assertEqual(record["rule_count"], 1)
        self.assertEqual(record["relations"][0]["requires"], ["rule_a", "rule_b"])
        self.assertEqual(record["relations"][0]["conflicts"], ["rule_c"])
        fields = record["disa_description"]
        self.assertEqual(fields["rule_field_counts"]["VulnDiscussion"], 1)
        self.assertEqual(fields["rule_field_counts"]["FalsePositives"], 1)
        self.assertEqual(fields["nonempty_rule_field_counts"]["VulnDiscussion"], 1)
        self.assertEqual(fields["nonempty_rule_field_counts"]["Documentable"], 1)

    def test_malformed_or_non_publisher_description_is_not_promoted(self):
        element = ET.fromstring(f'<description xmlns="{crosswalk.XCCDF}">ordinary text</description>')
        fields, raw = crosswalk.parse_disa_description(element)
        self.assertEqual(fields, {})
        self.assertEqual(raw, "ordinary text")

    def test_corpus_audit_is_explicitly_environment_gated(self):
        source = __import__("os").environ.get("SCAP_NG_FULL65_SOURCE_ROOT")
        if not source:
            self.skipTest("set SCAP_NG_FULL65_SOURCE_ROOT to run the pinned 65-archive audit")
        report = crosswalk.build(Path(source), 65,
                                 "8c8e5dff860af6b1290ee9273a282db24278f8d5",
                                 None)
        self.assertEqual(report["summary"]["archives"], 65)
        self.assertEqual(report["summary"]["source_rules"], 8892)
        self.assertEqual(report["summary"]["rules_with_requires_or_conflicts"], 0)


if __name__ == "__main__":
    unittest.main()
