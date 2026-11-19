"""Focused source-fidelity tests for Issue #83's reusable crosswalk."""
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src/scap_ng_tools/converter/_v04_runtime"))
import build_issue83_source_crosswalk as crosswalk  # noqa: E402


class Issue83SourceCrosswalkTests(unittest.TestCase):
    def make_archive(self, directory: Path, *, requires="", conflicts="") -> Path:
        rule = f'''<xccdf:Rule xmlns:xccdf="{crosswalk.XCCDF}" id="xccdf:test_rule">
          <xccdf:requires idref="rule_a rule_b"/><xccdf:requires idref="rule_c"/><xccdf:conflicts idref="rule_d"/>
          <xccdf:title>Relationship witness</xccdf:title>
          <xccdf:description>&lt;VulnDiscussion&gt;Keep this discussion&lt;/VulnDiscussion&gt;&lt;FalsePositives&gt;&lt;/FalsePositives&gt;&lt;Documentable&gt;false&lt;/Documentable&gt;</xccdf:description>
        </xccdf:Rule>'''
        xml = f'''<ds:data-stream-collection xmlns:ds="{crosswalk.DS}" xmlns:xccdf="{crosswalk.XCCDF}" id="collection">
          <ds:component id="checklist"><xccdf:Benchmark id="benchmark" xccdf-version="1.2"><xccdf:Rule id="xccdf:test_rule">
          <xccdf:requires idref="rule_a rule_b"/><xccdf:requires idref="rule_c"/><xccdf:conflicts idref="rule_d"/>
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
        self.assertEqual(record["relations"][0]["requires"], [{"any_of": ["rule_a", "rule_b"]}, "rule_c"])
        self.assertEqual(record["relations"][0]["conflicts"], ["rule_d"])
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

class Issue83ConverterRelationshipTests(unittest.TestCase):
    def test_relationship_helper_preserves_order_and_empty_elements(self):
        from v04_source_metadata import source_relationships, validate_relationship_targets
        rule = ET.fromstring(f'<Rule xmlns="{crosswalk.XCCDF}" id="r"><requires idref=" a  b "/><conflicts idref="c"/></Rule>')
        self.assertEqual(source_relationships(rule), {
            "requires": [{"any_of": ["a", "b"]}], "conflicts": ["c"]})
        empty = ET.fromstring(f'<Rule xmlns="{crosswalk.XCCDF}" id="r2"/>')
        self.assertEqual(source_relationships(empty), {"requires": [], "conflicts": []})
        with self.assertRaisesRegex(ValueError, "requires element"):
            source_relationships(ET.fromstring(f'<Rule xmlns="{crosswalk.XCCDF}"><requires/></Rule>'))
        with self.assertRaisesRegex(ValueError, "duplicate IDs"):
            source_relationships(ET.fromstring(
                f'<Rule xmlns="{crosswalk.XCCDF}"><requires idref="a a"/></Rule>'))
        with self.assertRaisesRegex(ValueError, "one idref"):
            source_relationships(ET.fromstring(f'<Rule xmlns="{crosswalk.XCCDF}"><conflicts idref="a b"/></Rule>'))
        validate_relationship_targets(
            {"requires": [{"any_of": ["group-a", "rule-a"]}], "conflicts": ["rule-b"]},
            {"group-a": ET.Element(f'{{{crosswalk.XCCDF}}}Group'),
             "rule-a": ET.Element(f'{{{crosswalk.XCCDF}}}Rule'),
             "rule-b": ET.Element(f'{{{crosswalk.XCCDF}}}Rule')})
        with self.assertRaisesRegex(ValueError, "target is unresolved"):
            validate_relationship_targets({"requires": ["missing"], "conflicts": []}, {})
        with self.assertRaisesRegex(ValueError, "not a Rule or Group"):
            validate_relationship_targets(
                {"requires": ["benchmark"], "conflicts": []},
                {"benchmark": ET.Element(f'{{{crosswalk.XCCDF}}}Benchmark')})

    def test_group_relationships_are_inventoried_without_rule_flattening(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "group-witness.zip"
            xml = (
                f'<ds:data-stream-collection xmlns:ds="{crosswalk.DS}" '
                f'xmlns:xccdf="{crosswalk.XCCDF}" id="collection">'
                '<ds:component id="checklist"><xccdf:Benchmark id="benchmark" '
                'xccdf-version="1.2"><xccdf:Group id="group-a">'
                '<xccdf:requires idref="group-b group-c"/>'
                '<xccdf:conflicts idref="group-d"/></xccdf:Group>'
                '</xccdf:Benchmark></ds:component>'
                '<ds:data-stream id="stream" scap-version="1.4">'
                '<ds:checklists><ds:component-ref id="checklist" href="#checklist"/>'
                '</ds:checklists></ds:data-stream></ds:data-stream-collection>'
            ).encode()
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("witness.xml", xml)
            record = crosswalk.archive_record(path)
        self.assertEqual(record["relations"], [])
        self.assertEqual(record["group_relation_count"], 1)
        self.assertEqual(record["group_relations"][0]["source_group"], "group-a")
        self.assertEqual(record["group_relations"][0]["requires"],
                         [{"any_of": ["group-b", "group-c"]}])
        self.assertEqual(record["group_relations"][0]["conflicts"], ["group-d"])

    def test_group_relationships_fail_closed_until_canonical_mapping_exists(self):
        from scap_ng_tools.converter.direct04 import load_runtime
        group = ET.fromstring(
            f'<Group xmlns="{crosswalk.XCCDF}" id="group-a">'
            '<requires idref="group-b"/><Rule id="rule-a"/></Group>')
        source = type("Source", (), {
            "applicability_level": lambda self, item: None,
        })()
        with self.assertRaisesRegex(ValueError, "canonical non-flattening mapping: group-a"):
            load_runtime().native_group(source, group, {"rule-a": "native-rule-a"})

    def test_disa_parser_retains_empty_values_and_explicit_false(self):
        from v04_source_metadata import parse_disa_description
        element = ET.fromstring(
            f'<description xmlns="{crosswalk.XCCDF}">'
            '&lt;VulnDiscussion&gt;discussion&lt;/VulnDiscussion&gt;'
            '&lt;FalsePositives&gt;&lt;/FalsePositives&gt;'
            '&lt;Documentable&gt;false&lt;/Documentable&gt;'
            '</description>')
        parsed = parse_disa_description(element)
        self.assertTrue(parsed["parsed"])
        self.assertEqual(parsed["fields"], {
            "VulnDiscussion": "discussion", "FalsePositives": "", "Documentable": "false"})
        self.assertIn("Documentable", parsed["raw"])
