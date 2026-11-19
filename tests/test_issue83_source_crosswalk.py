"""Focused source-fidelity tests for Issue #83's reusable crosswalk."""
from pathlib import Path
import sys
import tempfile
import json
import unittest
from unittest.mock import patch
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

    def test_oval_inventory_distinguishes_direct_and_nested_deprecations(self):
        xsd = """<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
              xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
              targetNamespace="urn:test">
          <xs:element name="old_test"><xs:annotation><xs:appinfo>
            <oval:deprecated_info><oval:version>5.12</oval:version>
              <oval:reason>replaced</oval:reason></oval:deprecated_info>
          </xs:appinfo></xs:annotation></xs:element>
          <xs:complexType name="current_state"><xs:sequence><xs:element name="old_field">
            <xs:annotation><xs:appinfo><oval:deprecated_info>
              <oval:version>5.11.1:1.1</oval:version><oval:reason>field only</oval:reason>
            </oval:deprecated_info></xs:appinfo></xs:annotation>
          </xs:element></xs:sequence></xs:complexType>
        </xs:schema>""".encode()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "test-definitions-schema.xsd").write_bytes(xsd)
            report = crosswalk.oval_inventory(root)
        rows = {row["name"]: row for row in report["declarations"]}
        self.assertEqual(report["summary"]["native_mapping_status"],
                         {"deprecated": 1, "unclassified": 1})
        self.assertEqual(rows["old_test"]["deprecation"][0]["version"], "5.12")
        self.assertEqual(rows["current_state"]["native_mapping_status"], "unclassified")
        self.assertEqual(rows["current_state"]["deprecated_members"][0]["name"], "old_field")
        self.assertEqual(rows["current_state"]["deprecated_members"][0]["scope"], "nested")
        self.assertIsNone(rows["current_state"]["deprecated_members"][0]["value"])
        self.assertEqual(report["summary"]["official_deprecation_annotations"], 2)

    def test_pinned_oval_deprecation_inventory_is_environment_gated(self):
        source = __import__("os").environ.get("SCAP_NG_OVAL_SCHEMA_ROOT")
        if not source:
            self.skipTest("set SCAP_NG_OVAL_SCHEMA_ROOT to the pinned OVAL schema checkout")
        report = crosswalk.oval_inventory(Path(source))
        self.assertEqual(report["source_commit_expected"],
                         "2f140ee5c5dd1ed9606fcd5afc301f6baeb48706")
        self.assertEqual(report["summary"]["schema_files"], 23)
        self.assertGreater(report["summary"]["official_deprecation_annotations"], 0)
        direct = next(row for row in report["declarations"]
                      if row["name"] == "rpmverify_test")
        self.assertEqual(direct["native_mapping_status"], "deprecated")
        md5 = next(row for row in report["declarations"]
                   if row["name"] == "rpmverifyfile_state")
        member = next(row for row in md5["deprecated_members"]
                      if row["name"] == "md5_differs")
        self.assertEqual(member["version"], "5.11.1:1.1")
        behaviors = next(row for row in report["declarations"]
                         if row["name"] == "FileBehaviors")
        upward = next(row for row in behaviors["deprecated_members"]
                      if row["value"] == "up")
        self.assertEqual(upward["version"], "5.12.3")
        self.assertIn("being removed", upward["reason"])

    def test_published_oval_deprecation_receipt_is_pinned(self):
        receipt = json.loads((ROOT / "docs/evidence/issue83/oval-schema-deprecation-summary.json").read_text())
        self.assertEqual(receipt["source"]["commit"],
                         "2f140ee5c5dd1ed9606fcd5afc301f6baeb48706")
        self.assertEqual(receipt["source"]["schema_manifest_sha256"],
                         "5b71250dd5fe97dca2776e94fba2b0a3f5decea3707c672fc402836324e24721")
        self.assertEqual(receipt["inventory"]["declarations"], 1033)
        self.assertEqual(receipt["inventory"]["native_mapping_status"],
                         {"deprecated": 215, "unclassified": 818})
        self.assertIn("does not authorize conversion", receipt["semantics"]["conversion"])

    def test_relationship_crosswalk_pins_official_xccdf_schema(self):
        self.assertEqual(crosswalk.XCCDF_SCHEMA_URL,
                         "https://scap.nist.gov/schema/xccdf/1.2/xccdf_1.2.xsd")
        self.assertEqual(len(crosswalk.XCCDF_SCHEMA_SHA256), 64)
        receipt = json.loads((ROOT / "docs/evidence/issue83/source-crosswalk-summary.json").read_text())
        self.assertEqual(receipt["source"]["xccdf_schema"]["sha256"], crosswalk.XCCDF_SCHEMA_SHA256)


if __name__ == "__main__":
    unittest.main()

class Issue83ConverterRelationshipTests(unittest.TestCase):
    def test_production_rule_renderer_emits_source_relationships(self):
        from scap_ng_tools.converter.direct04 import load_runtime
        runtime = load_runtime()
        rule = ET.fromstring(
            f'<Rule xmlns="{crosswalk.XCCDF}" id="rule-a"><version>1</version>'
            '<title>Production relationship witness</title>'
            '<description>before<em>middle</em>after</description>'
            '<requires idref="rule-b rule-c"/><conflicts idref="rule-d"/>'
            f'<check system="{runtime.OVAL}"><check-content-ref href="#oval" name="definition-a"/></check>'
            '</Rule>')
        definition = ET.Element('{urn:oval}definition', {'class': 'compliance'})
        source_nodes = {'rule-a': rule, 'rule-b': ET.Element(f'{{{crosswalk.XCCDF}}}Rule'),
                        'rule-c': ET.Element(f'{{{crosswalk.XCCDF}}}Rule'),
                        'rule-d': ET.Element(f'{{{crosswalk.XCCDF}}}Rule'),
                        'definition-a': definition}

        class Source:
            benchmark_component = 'benchmark'
            def __init__(self):
                self.rules = {'rule-a': rule}
                self.nodes = {'benchmark': source_nodes}
            def automated_check(self, _rule):
                return 'oval', 'definition-a', []
            def node(self, _component, identifier, _kind):
                return self.nodes['benchmark'][identifier]
            def applicability_level(self, _item):
                return None
            def applicability_context(self, _item):
                return []
            def manual_checks(self, _rule):
                return []

        class FixtureAssessment:
            def __init__(self, *_args, **_kwargs):
                self.tests = {}
                self.shared_objects = {}
                self.variables = {}
                self.inputs = {}
                self.input_bindings = {}
                self.policy_parameters = {}
                self.used = {}
                self.conversion_warnings = []
                self.human_compaction = []
                self.selector_equivalences = []
                self.enum_variable_equivalences = []
                self.native_names = {}
                self.synthetic_variables = []
                self.inlined_variables = []
            def reference(self, _identifier, _kind):
                return {'not_evaluated': {'reason': 'fixture'}}

        with patch.object(runtime, 'AssessmentConverter', FixtureAssessment):
            documents, _binding = runtime.convert_rule(Source(), 'rule-a', [])
        native = next(value['rule'] for value in documents.values() if 'rule' in value)
        self.assertEqual(native['requires'], [{'any_of': ['rule-b', 'rule-c']}])
        self.assertEqual(native['conflicts'], ['rule-d'])
        self.assertEqual(native['discussion'], 'beforemiddleafter')

    def test_manual_rule_renderer_emits_the_same_relationship_contract(self):
        from v04_direct_scap_source import OCIL
        from scap_ng_tools.converter.manual04 import manual_rule
        rule = ET.fromstring(
            f'<Rule xmlns="{crosswalk.XCCDF}" id="manual-a"><version>1</version>'
            '<title>Manual relationship witness</title>'
            '<requires idref="rule-b rule-c"/><conflicts idref="rule-d"/>'
            f'<check system="{OCIL}" selector="manual"><check-content>Do it.</check-content></check>'
            '</Rule>')
        target_nodes = {'manual-a': rule,
                        'rule-b': ET.Element(f'{{{crosswalk.XCCDF}}}Rule'),
                        'rule-c': ET.Element(f'{{{crosswalk.XCCDF}}}Rule'),
                        'rule-d': ET.Element(f'{{{crosswalk.XCCDF}}}Rule')}
        source = type('Source', (), {
            'nodes': {'benchmark': target_nodes}, 'benchmark_component': 'benchmark',
            'catalog': {}, 'components': {},
        })()
        documents, _binding = manual_rule(
            source, rule, title='Manual relationship witness',
            rule_id='manual-rule', assessment_id='manual-assessment')
        native = documents['authoring/direct-slice/rules/manual-rule.json']['rule']
        self.assertEqual(native['requires'], [{'any_of': ['rule-b', 'rule-c']}])
        self.assertEqual(native['conflicts'], ['rule-d'])

    def test_relationship_helper_preserves_order_and_empty_elements(self):
        from v04_source_metadata import source_description_text, source_relationships, validate_relationship_targets
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
        rule = ET.fromstring(
            f'<Rule xmlns="{crosswalk.XCCDF}"><description>before<em>middle</em>after</description></Rule>')
        self.assertEqual(source_description_text(rule), 'beforemiddleafter')

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
