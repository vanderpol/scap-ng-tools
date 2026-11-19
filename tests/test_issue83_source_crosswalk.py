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
          <xccdf:ident system="http://example.test/ident">ID-1</xccdf:ident>
          <xccdf:reference href="https://example.test">REF-1</xccdf:reference>
          <xccdf:fix id="fix-1">echo fix</xccdf:fix>
          <xccdf:fixtext fixref="fix-1">Apply the fix</xccdf:fixtext>
          <xccdf:description>&lt;VulnDiscussion&gt;Keep this discussion&lt;/VulnDiscussion&gt;&lt;FalsePositives&gt;&lt;/FalsePositives&gt;&lt;Documentable&gt;false&lt;/Documentable&gt;</xccdf:description>
        </xccdf:Rule>'''
        xml = f'''<ds:data-stream-collection xmlns:ds="{crosswalk.DS}" xmlns:xccdf="{crosswalk.XCCDF}" id="collection">
          <ds:component id="checklist"><xccdf:Benchmark id="benchmark" xccdf-version="1.2"><xccdf:Rule id="xccdf:test_rule">
          <xccdf:requires idref="rule_a rule_b"/><xccdf:requires idref="rule_c"/><xccdf:conflicts idref="rule_d"/>
            <xccdf:title>Relationship witness</xccdf:title>
            <xccdf:ident system="http://example.test/ident">ID-1</xccdf:ident>
            <xccdf:reference href="https://example.test">REF-1</xccdf:reference>
            <xccdf:fix id="fix-1">echo fix</xccdf:fix>
            <xccdf:fixtext fixref="fix-1">Apply the fix</xccdf:fixtext>
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
        metadata = record["xccdf_metadata"]
        self.assertEqual(metadata["rule_field_counts"], {
            "fix": 1, "fixtext": 1, "ident": 1, "reference": 1,
        })
        self.assertEqual(metadata["element_counts"], metadata["rule_field_counts"])
        self.assertEqual(len(record["rules"][0]["xccdf_metadata_field_sha256"]["fixtext"]), 1)

    def test_mixed_description_text_is_not_truncated(self):
        element = ET.fromstring(
            f'<description xmlns="{crosswalk.XCCDF}">&lt;VulnDiscussion&gt;before'
            '&lt;/VulnDiscussion&gt;<em>middle</em>&lt;Documentable&gt;false'
            '&lt;/Documentable&gt;</description>')
        fields, raw = crosswalk.parse_disa_description(element)
        self.assertEqual(raw, '<VulnDiscussion>before</VulnDiscussion>middle<Documentable>false</Documentable>')
        self.assertEqual(fields['VulnDiscussion'], 'before')
        self.assertEqual(fields['Documentable'], 'false')

    def test_disa_diagnostic_classifies_malformed_publisher_xml_without_body(self):
        diagnostic = crosswalk.diagnose_disa_description(
            '<VulnDiscussion>literal <tag></VulnDiscussion>')
        self.assertEqual(diagnostic['category'], 'source_embedded_publisher_payload_malformed')
        self.assertRegex(diagnostic['error'], r'line \d+, column \d+')

    def test_malformed_or_non_publisher_description_is_not_promoted(self):
        element = ET.fromstring(f'<description xmlns="{crosswalk.XCCDF}">ordinary text</description>')
        fields, raw = crosswalk.parse_disa_description(element)
        self.assertEqual(fields, {})
        self.assertEqual(raw, "ordinary text")
        diagnostic = crosswalk.diagnose_disa_description("literal <unclosed>")
        self.assertEqual(diagnostic["category"], "unrecognized_publisher_payload")

    def test_malformed_disa_payload_requires_a_recognized_marker(self):
        diagnostic = crosswalk.diagnose_disa_description(
            "<VulnDiscussion>literal <tag></VulnDiscussion>")
        self.assertEqual(diagnostic["category"], "source_embedded_publisher_payload_malformed")
        diagnostic = crosswalk.diagnose_disa_description("<Host><Context>")
        self.assertEqual(diagnostic["category"], "unrecognized_publisher_payload")

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
                         {"deprecated_migration": 1, "unproven": 1})
        self.assertEqual(report["summary"]["unclassified_declarations"], 0)
        self.assertEqual(rows["old_test"]["deprecation"][0]["version"], "5.12")
        self.assertEqual(rows["current_state"]["native_mapping_status"], "unproven")
        self.assertEqual(rows["current_state"]["disposition"]["runtime_equivalence"],
                         "not_proved")
        self.assertEqual(rows["current_state"]["disposition"]["native_schema_pointer"],
                         "not_assessed")
        self.assertEqual(rows["current_state"]["disposition"]["required_witnesses"]["positive"],
                         "source-valid minimal closure")
        self.assertEqual(rows["current_state"]["disposition"]["ri_obligation"],
                         "not_assessed")
        self.assertEqual(rows["current_state"]["deprecated_members"][0]["name"], "old_field")
        shape = rows["current_state"]["schema_shape"]
        self.assertEqual(shape["kind"], "complexType")
        self.assertEqual(shape["children"][0]["kind"], "sequence")
        field = shape["children"][0]["children"][0]
        self.assertEqual(field["attributes"]["name"], "old_field")
        self.assertEqual(rows["current_state"]["schema_shape_sha256"],
                         crosswalk._schema_shape_digest(shape))
        self.assertGreater(rows["current_state"]["grammar_row_count"], 1)
        field_row = next(item for item in report["grammar_rows"]
                         if item["source_name"] == "old_field")
        self.assertEqual(field_row["source_kind"], "element")
        self.assertEqual(field_row["disposition"], "deprecated_migration")
        self.assertEqual(report["summary"]["grammar_rows"], len(report["grammar_rows"]))
        self.assertIn("cardinality and attribute-use metadata",
                      report["summary"]["schema_shape_contract"]["preserves"])
        self.assertEqual(rows["current_state"]["deprecated_members"][0]["scope"], "nested")
        self.assertIsNone(rows["current_state"]["deprecated_members"][0]["value"])
        self.assertEqual(report["summary"]["official_deprecation_annotations"], 2)
        self.assertEqual(report["summary"]["schema_dependencies"], 0)
        self.assertEqual(report["summary"]["schema_manifest_files"], 1)
        self.assertEqual(report["summary"]["unresolved_schema_dependencies"], 0)
        self.assertEqual(report["schema_manifest"][0]["schema_file"],
                         "test-definitions-schema.xsd")

    def test_schema_shape_preserves_defaults_cardinality_and_base_relationships(self):
        xsd = """<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"
              targetNamespace=\"urn:test\">
          <xs:complexType name=\"derived_state\"><xs:complexContent>
            <xs:extension base=\"base_state\"><xs:sequence>
              <xs:element name=\"value\" type=\"xs:string\" minOccurs=\"0\" maxOccurs=\"unbounded\" default=\"x\"/>
            </xs:sequence><xs:attribute name=\"mode\" use=\"required\" default=\"strict\"/>
            </xs:extension></xs:complexContent></xs:complexType>
        </xs:schema>""".encode()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "test-definitions-schema.xsd").write_bytes(xsd)
            row = next(row for row in crosswalk.oval_inventory(root)["declarations"]
                       if row["name"] == "derived_state")
        extension = row["schema_shape"]["children"][0]["children"][0]
        self.assertEqual(extension["kind"], "extension")
        self.assertEqual(extension["attributes"]["base"], "base_state")
        sequence = extension["children"][0]
        value = sequence["children"][0]
        self.assertEqual(value["attributes"]["maxOccurs"], "unbounded")
        self.assertEqual(value["attributes"]["default"], "x")
        attribute = extension["children"][1]
        self.assertEqual(attribute["attributes"]["use"], "required")
        self.assertEqual(attribute["attributes"]["default"], "strict")
        derivation = row["schema_derivation_contract"]
        self.assertEqual(derivation["rows"][0]["kind"], "extension")
        self.assertEqual(derivation["rows"][0]["attributes"]["base"], "base_state")
        self.assertEqual(derivation["status"], "structural_only")
        self.assertEqual(derivation["semantics"], "not_interpreted")

    def test_schema_qnames_resolve_local_bases_and_preserve_external_builtins(self):
        xsd = """<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"
              xmlns:t=\"urn:test\" targetNamespace=\"urn:test\">
          <xs:complexType name=\"base_state\"><xs:sequence>
            <xs:element name=\"base_value\" type=\"xs:string\"/>
          </xs:sequence></xs:complexType>
          <xs:complexType name=\"derived_state\"><xs:complexContent>
            <xs:extension base=\"t:base_state\"><xs:sequence>
              <xs:element name=\"value\" type=\"xs:int\"/>
            </xs:sequence></xs:extension>
          </xs:complexContent></xs:complexType>
        </xs:schema>""".encode()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "test-definitions-schema.xsd").write_bytes(xsd)
            report = crosswalk.oval_inventory(root)
        derived = next(row for row in report["declarations"]
                       if row["name"] == "derived_state")
        base = next(reference for reference in derived["schema_references"]
                    if reference["attribute"] == "base")
        self.assertEqual(base["status"], "resolved")
        self.assertEqual(base["target_name"], "base_state")
        self.assertEqual(derived["schema_inheritance"]["base_chain"][0]["name"],
                         "base_state")
        self.assertEqual(derived["schema_inheritance"]["status"], "resolved")
        members = derived["schema_effective_members"]["members"]
        self.assertEqual([member["name"] for member in members],
                         ["base_value", "value"])
        self.assertEqual([member["origin"] for member in members],
                         ["inherited", "direct"])
        self.assertEqual(members[0]["attributes"]["type"],
                         "xs:string")
        self.assertEqual(derived["schema_effective_members"]["status"], "resolved")
        builtin = next(reference for reference in derived["schema_references"]
                       if reference["attribute"] == "type" and
                       reference["target_name"] == "int")
        self.assertEqual(builtin["status"], "external_builtin")
        self.assertEqual(report["summary"]["resolved_schema_references"], 1)
        self.assertEqual(report["summary"]["unresolved_schema_references"], 0)

    def test_schema_semantics_inventory_preserves_schematron_and_prose_as_holds(self):
        xsd = """<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"
              xmlns:sch=\"http://purl.oclc.org/dsdl/schematron\"
              targetNamespace=\"urn:test\">
          <xs:annotation><xs:documentation>Field meaning</xs:documentation></xs:annotation>
          <sch:pattern id=\"p1\"><sch:rule context=\"t:item\">
            <sch:assert test=\"@id\">An id is required</sch:assert>
          </sch:rule></sch:pattern>
          <xs:element name=\"item\"/>
        </xs:schema>""".encode()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "test-definitions-schema.xsd").write_bytes(xsd)
            report = crosswalk.oval_inventory(root)
        semantic = report["schema_semantics"]
        self.assertEqual(semantic["summary"]["schematron_patterns"], 1)
        self.assertEqual(semantic["summary"]["schematron_rules"], 1)
        self.assertEqual(semantic["summary"]["schematron_assertions"], 1)
        self.assertEqual(semantic["summary"]["prose_rows"], 1)
        assertion = next(row for row in semantic["schematron"]
                         if row["kind"] == "assert")
        self.assertEqual(assertion["attributes"]["test"], "@id")
        self.assertEqual(assertion["test_feature_tags"], ["attribute_reference"])
        self.assertEqual(assertion["namespace_bindings"]["sch"],
                         crosswalk.SCHEMATRON)
        self.assertIn("schema[0]/pattern[1]/rule[0]/assert[0]",
                      assertion["source_path"])
        self.assertEqual(assertion["disposition"], "not_interpreted")
        self.assertEqual(semantic["disposition"]["status"], "inventory_only")

    def test_schema_keyref_refer_resolves_identity_constraint(self):
        xsd = """<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"
              xmlns:t=\"urn:test\" targetNamespace=\"urn:test\">
          <xs:element name=\"catalog\"><xs:key name=\"entryKey\">
            <xs:selector xpath=\"t:entry\"/><xs:field xpath=\"@id\"/>
          </xs:key><xs:keyref name=\"entryRef\" refer=\"t:entryKey\">
            <xs:selector xpath=\"t:ref\"/><xs:field xpath=\"@id\"/>
          </xs:keyref></xs:element>
        </xs:schema>""".encode()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "test-definitions-schema.xsd").write_bytes(xsd)
            report = crosswalk.oval_inventory(root)
        catalog = report["declarations"][0]
        refer = next(reference for reference in catalog["schema_references"]
                     if reference["attribute"] == "refer")
        self.assertEqual(refer["status"], "resolved")
        self.assertEqual(refer["target_name"], "entryKey")
        self.assertEqual(report["summary"]["unresolved_schema_references"], 0)

    def test_schema_qname_unknown_prefix_is_not_treated_as_local(self):
        xsd = """<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"
              targetNamespace=\"urn:test\">
          <xs:complexType name=\"derived_state\"><xs:complexContent>
            <xs:extension base=\"missing:base_state\"/>
          </xs:complexContent></xs:complexType>
        </xs:schema>""".encode()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "test-definitions-schema.xsd").write_bytes(xsd)
            report = crosswalk.oval_inventory(root)
        derived = report["declarations"][0]
        base = derived["schema_inheritance"]["unresolved_bases"][0]
        self.assertEqual(base["status"], "unresolved_prefix")
        self.assertEqual(report["summary"]["unresolved_schema_references"], 1)

    def test_canonical_mapping_index_is_explicitly_unproven(self):
        xsd = """<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"
              targetNamespace=\"http://oval.mitre.org/XMLSchema/oval-definitions-5#foo\"><xs:element name=\"foo_test\"/>
        </xs:schema>""".encode()
        item_xsd = """<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"
              targetNamespace=\"http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#foo\"><xs:element name=\"foo_item\"/>
        </xs:schema>""".encode()
        mapping = {
            "capability": "test.foo",
            "specification_version": "0.4.1",
            "source": {
                "language": "OVAL 5.12.3",
                "upstream_commit": "source-pin",
                "definitions_schema": "third_party/foo/test-definitions-schema.xsd",
                "namespace": "http://oval.mitre.org/XMLSchema/oval-definitions-5#foo",
                "test": "foo_test",
                "item": "foo_item",
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "test-definitions-schema.xsd").write_bytes(xsd)
            (root / "test-system-characteristics-schema.xsd").write_bytes(item_xsd)
            mappings = root / "mappings"
            mappings.mkdir()
            mapping_path = mappings / "foo.json"
            mapping_path.write_text(json.dumps(mapping))
            report = crosswalk.oval_inventory(root, mappings, "canonical-pin")
        self.assertEqual(report["summary"]["canonical_mapping_rows"], 2)
        self.assertEqual(report["summary"]["grammar_rows_with_mapping"], 2)
        row = next(item for item in report["grammar_rows"]
                   if item["source_name"] == "foo_test")
        self.assertEqual(row["mapping_disposition"], "mapped_unproven")
        self.assertEqual(row["canonical_mapping_candidates"][0]["capability"], "test.foo")
        self.assertEqual(row["canonical_mapping_candidates"][0]["converter_proof"], "not_run")
        self.assertEqual(row["canonical_mapping_candidates"][0]["source_language"], "OVAL 5.12.3")
        self.assertEqual(row["canonical_mapping_candidates"][0]["source_upstream_commit"], "source-pin")
        self.assertEqual(row["canonical_mapping_candidates"][0]["field_mapping_status"],
                         "declared_unproven")
        self.assertIsInstance(row["canonical_mapping_candidates"][0]["source_member_names"], list)
        item_row = next(item for item in report["grammar_rows"]
                        if item["source_name"] == "foo_item")
        self.assertEqual(item_row["schema_file"], "test-system-characteristics-schema.xsd")
        self.assertEqual(item_row["canonical_mapping_candidates"][0]["source_role"], "item")
        self.assertEqual(report["summary"]["canonical_mapping_commit"], "canonical-pin")

    def test_schema_dependency_inventory_records_resolved_and_missing_edges(self):
        xsd = """<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"
              targetNamespace=\"urn:test\"><xs:import schemaLocation=\"base.xsd\"/>
              <xs:include schemaLocation=\"missing.xsd\"/></xs:schema>""".encode()
        base = b'<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"/>'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "test-definitions-schema.xsd").write_bytes(xsd)
            (root / "base.xsd").write_bytes(base)
            report = crosswalk.oval_inventory(root)
        edges = report["schema_dependencies"]
        self.assertEqual(len(edges), 2)
        self.assertEqual([edge["resolved"] for edge in edges], [True, False])
        resolved = next(edge for edge in edges if edge["resolved"])
        self.assertEqual(resolved["target_schema"], "base.xsd")
        self.assertEqual(len(resolved["target_schema_sha256"]), 64)
        missing = next(edge for edge in edges if not edge["resolved"])
        self.assertEqual(missing["schema_location"], "missing.xsd")
        self.assertEqual(report["summary"]["unresolved_schema_dependencies"], 1)

    def test_pinned_oval_deprecation_inventory_is_environment_gated(self):
        source = __import__("os").environ.get("SCAP_NG_OVAL_SCHEMA_ROOT")
        if not source:
            self.skipTest("set SCAP_NG_OVAL_SCHEMA_ROOT to the pinned OVAL schema checkout")
        report = crosswalk.oval_inventory(Path(source))
        self.assertEqual(report["source_commit_expected"],
                         "2f140ee5c5dd1ed9606fcd5afc301f6baeb48706")
        self.assertEqual(report["summary"]["schema_files"], 46)
        self.assertEqual(report["summary"]["definition_schema_files"], 23)
        self.assertEqual(report["summary"]["system_characteristics_schema_files"], 23)
        self.assertGreater(report["summary"]["official_deprecation_annotations"], 0)
        direct = next(row for row in report["declarations"]
                      if row["name"] == "rpmverify_test")
        self.assertEqual(direct["native_mapping_status"], "deprecated_migration")
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

    def test_oval_content_inventory_preserves_source_identity_and_authored_controls(self):
        xml = f"""<oval:oval_definitions xmlns:oval=\"{crosswalk.OVAL_DEFINITIONS}\"
              xmlns:ind=\"{crosswalk.OVAL_DEFINITIONS}#independent\">
          <oval:definitions>
            <oval:definition id=\"oval:test:def:1\" class=\"compliance\"/>
          </oval:definitions>
          <oval:variables>
            <oval:external_variable id=\"oval:test:var:1\" datatype=\"string\">
              <oval:possible_restriction><oval:restriction operation=\"pattern match\">^x$</oval:restriction></oval:possible_restriction>
            </oval:external_variable>
          </oval:variables>
          <oval:objects><ind:variable_object id=\"oval:test:obj:1\">
            <oval-def:filter xmlns:oval-def=\"http://oval.mitre.org/XMLSchema/oval-definitions-5\">oval:test:ste:1</oval-def:filter>
          </ind:variable_object></oval:objects>
          <oval:states><ind:variable_state id=\"oval:test:ste:1\"/></oval:states>
          <oval:tests>
            <ind:variable_test id=\"oval:test:tst:1\" check=\"at least one\"
                check_existence=\"all_exist\" var_check=\"all\" object_ref=\"oval:test:obj:1\"/>
          </oval:tests>
        </oval:oval_definitions>""".encode()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "content"
            root.mkdir()
            source = root / "agnostic-test.xml"
            source.write_bytes(xml)
            report = crosswalk.oval_content_inventory(root, "source-pin")
            repeat = crosswalk.oval_content_inventory(root, "source-pin")
        self.assertEqual(report, repeat)
        self.assertEqual(report["summary"]["xml_files"], 1)
        self.assertEqual(report["summary"]["embedded_xml_members"], 0)
        self.assertEqual(report["summary"]["source_documents"], 1)
        self.assertEqual(report["summary"]["definitions"], 1)
        self.assertEqual(report["summary"]["tests"], 1)
        self.assertEqual(report["summary"]["variables"], 1)
        self.assertEqual(report["summary"]["object_components"], 1)
        self.assertEqual(report["summary"]["state_components"], 1)
        self.assertEqual(report["summary"]["test_tags"], {"variable_test": 1})
        self.assertEqual(report["summary"]["variable_tags"], {"external_variable": 1})
        self.assertEqual(report["summary"]["variable_child_tags"], {"possible_restriction": 1})
        self.assertEqual(report["variables"][0]["restriction_operations"], ["pattern match"])
        self.assertEqual(report["summary"]["authored_test_attributes"], {
            "check": 1, "check_existence": 1, "var_check": 1})
        definition = report["definitions"][0]
        test = report["tests"][0]
        self.assertEqual(definition["source_id"], "oval:test:def:1")
        self.assertEqual(test["source_id"], "oval:test:tst:1")
        self.assertEqual({reference["reference_kind"] for reference in test["source_references"]},
                         {"boolean_control", "object_ref"})
        controls = next(reference for reference in test["source_references"]
                        if reference["reference_kind"] == "boolean_control")
        self.assertEqual(controls["controls"]["check"], "at least one")
        object_row = report["objects"][0]
        self.assertEqual(object_row["source_references"][0]["reference_kind"],
                         "filter_state_ref")
        self.assertEqual(object_row["source_references"][0]["value"],
                         "oval:test:ste:1")
        self.assertEqual(len(definition["source_file_sha256"]), 64)
        self.assertEqual(len(test["source_element_sha256"]), 64)
        self.assertEqual(report["qualification"]["expected_outcomes"], "not_inferred")

    def test_oval_content_inventory_includes_embedded_definition_members(self):
        xml = f"""<oval:oval_definitions xmlns:oval=\"{crosswalk.OVAL_DEFINITIONS}\">
          <oval:definitions><oval:definition id=\"oval:test:def:zip\"/></oval:definitions>
        </oval:oval_definitions>""".encode()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "content"
            root.mkdir()
            archive = root / "oval-def-ext.zip"
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
                package.writestr("oval-def-ext.xml", xml)
            report = crosswalk.oval_content_inventory(root, "source-pin")
        self.assertEqual(report["summary"]["xml_files"], 0)
        self.assertEqual(report["summary"]["embedded_xml_members"], 1)
        self.assertEqual(report["summary"]["source_documents"], 1)
        self.assertEqual(report["summary"]["definitions"], 1)
        self.assertIn("!oval-def-ext.xml", report["definitions"][0]["source_file"])
        self.assertEqual(len(report["definitions"][0]["source_member_sha256"]), 64)

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
        from v04_source_metadata import source_standard_metadata
        runtime = load_runtime()
        rule = ET.fromstring(
            f'<Rule xmlns="{crosswalk.XCCDF}" id="rule-a"><version>1</version>'
            '<title>Production relationship witness</title>'
            '<description>before<em>middle</em>after</description>'
            '<ident system="cce">CCE-123</ident>'
            '<reference href="https://example.invalid/ref">Reference text</reference>'
            '<fix system="bash" reboot="false">echo fix</fix>'
            '<fixtext fixref="fix-1">Fix text <em>with markup</em></fixtext>'
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
        metadata = _binding['source_standard_metadata']
        self.assertEqual([row['kind'] for row in metadata],
                         ['ident', 'reference', 'fix', 'fixtext'])
        self.assertEqual([row['ordinal'] for row in metadata], [4, 5, 6, 7])
        self.assertEqual(metadata[0]['attributes'], {'system': 'cce'})
        self.assertEqual(metadata[0]['text'], 'CCE-123')
        self.assertEqual(metadata[3]['text'], 'Fix text with markup')
        for row in metadata:
            self.assertRegex(row['source_xml_sha256'], r'^[0-9a-f]{64}$')
        altered = ET.fromstring(
            f'<Rule xmlns="{crosswalk.XCCDF}"><fixtext>Different <em>tail</em> text</fixtext></Rule>')
        self.assertNotEqual(metadata[3]['source_xml_sha256'],
                            source_standard_metadata(altered)[0]['source_xml_sha256'])
        self.assertNotIn('source_standard_metadata', native)

    def test_standard_xccdf_metadata_helper_preserves_order_duplicates_and_absence(self):
        from v04_source_metadata import source_standard_metadata
        rule = ET.fromstring(
            f'<Rule xmlns="{crosswalk.XCCDF}"><title>metadata</title>'
            '<ident system="cce">one</ident><ident system="cce">two</ident>'
            '<reference href="ref">reference</reference>'
            '<fix system="shell" reboot="true">apply</fix>'
            '<fixtext fixref="f">explain</fixtext></Rule>')
        rows = source_standard_metadata(rule)
        self.assertEqual([row['kind'] for row in rows],
                         ['ident', 'ident', 'reference', 'fix', 'fixtext'])
        self.assertEqual([row['ordinal'] for row in rows], [2, 3, 4, 5, 6])
        self.assertEqual([row['text'] for row in rows],
                         ['one', 'two', 'reference', 'apply', 'explain'])
        self.assertEqual(rows[0]['attributes'], {'system': 'cce'})
        self.assertEqual(rows[2]['attributes'], {'href': 'ref'})
        self.assertEqual(rows[4]['attributes'], {'fixref': 'f'})
        for row in rows:
            self.assertRegex(row['source_xml_sha256'], r'^[0-9a-f]{64}$')
        foreign = ET.fromstring(
            f'<Rule xmlns="{crosswalk.XCCDF}" xmlns:v="urn:vendor">'
            '<v:fixtext>foreign</v:fixtext><fixtext>native</fixtext></Rule>')
        self.assertEqual([row['text'] for row in source_standard_metadata(foreign)], ['native'])
        self.assertEqual(source_standard_metadata(ET.fromstring(
            f'<Rule xmlns="{crosswalk.XCCDF}"><title>none</title></Rule>')), [])

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

    def test_manual_rule_renderer_preserves_standard_metadata_in_provenance(self):
        from v04_direct_scap_source import OCIL
        from scap_ng_tools.converter.manual04 import manual_rule
        rule = ET.fromstring(
            f'<Rule xmlns="{crosswalk.XCCDF}" id="manual-metadata"><version>1</version>'
            '<title>Manual metadata witness</title>'
            '<ident system="cce">CCE-MANUAL</ident>'
            '<reference href="https://example.invalid/manual">Manual reference</reference>'
            '<fix system="shell">echo manual</fix>'
            '<fixtext fixref="manual-fix">Manual fix text</fixtext>'
            f'<check system="{OCIL}" selector="manual">'
            '<check-content>Review the setting.</check-content></check></Rule>')
        target_nodes = {'manual-metadata': rule}
        source = type("Source", (), {
            'nodes': {'benchmark': target_nodes}, 'benchmark_component': 'benchmark',
            'catalog': {}, 'components': {},
        })()
        documents, binding = manual_rule(
            source, rule, title='Manual metadata witness', rule_id='manual-rule',
            assessment_id='manual-assessment')
        metadata = binding['source_standard_metadata']
        self.assertEqual([row['kind'] for row in metadata],
                         ['ident', 'reference', 'fix', 'fixtext'])
        self.assertEqual([row['text'] for row in metadata],
                         ['CCE-MANUAL', 'Manual reference', 'echo manual', 'Manual fix text'])
        native = documents['authoring/direct-slice/rules/manual-rule.json']['rule']
        self.assertNotIn('source_standard_metadata', native)

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

    def test_disa_source_metadata_parser_preserves_mixed_content(self):
        from v04_source_metadata import parse_disa_description
        element = ET.fromstring(
            f'<description xmlns="{crosswalk.XCCDF}">'
            '&lt;VulnDiscussion&gt;before&lt;/VulnDiscussion&gt;'
            '<em>middle</em>&lt;Documentable&gt;false&lt;/Documentable&gt;'
            '</description>')
        parsed = parse_disa_description(element)
        self.assertEqual(parsed["raw"], '<VulnDiscussion>before</VulnDiscussion>middle<Documentable>false</Documentable>')
        self.assertEqual(parsed["fields"]["Documentable"], "false")

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
