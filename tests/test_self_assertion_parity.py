"""Independent fixture tests for the full OVAL Test Content parity gate."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_self_assertion_parity import (PREFIX, PIN, audit, digest, slug, sources,
    parse_oval, reachable_source_tests, normalize_source_evaluate, normalize_native_evaluate)

SOURCE_ID = "oval:example:def:1"
TEST_ID = "oval:example:tst:1"
SOURCE_PATH = PREFIX + "agnostic/sample.xml"
XML = (b'<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">'
       b'<definitions><definition id="oval:example:def:1">'
       b'<criteria operator="AND"><criterion test_ref="oval:example:tst:1"/>'
       b'</criteria></definition></definitions>'
       b'<tests><variable_test id="oval:example:tst:1" check="all" '
       b'check_existence="at_least_one_exists"><object object_ref="oval:example:obj:1"/>'
       b'</variable_test></tests>'
       b'<objects><variable_object id="oval:example:obj:1">'
       b'<var_ref>oval:example:var:1</var_ref></variable_object></objects>'
       b'<variables><constant_variable id="oval:example:var:1" datatype="string">'
       b'<value>sample</value></constant_variable></variables></oval_definitions>')

class FullOriginalSourceParityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.src = self.root / "source"
        source = self.src / "agnostic" / "sample.xml"
        source.parent.mkdir(parents=True)
        source.write_bytes(XML)
        self.pack = self.root / "pack"
        self.pack.mkdir()
        (self.pack / "manifest.json").write_text(json.dumps({
            "source_commit": PIN,
            "schema": {"aggregate_sha256": "fixture-schema-digest"},
        }))
        self.row = {"source_path": SOURCE_PATH, "source_sha256": digest(XML),
                    "definition_id": SOURCE_ID,
                    "source_test_ids": [TEST_ID],
                    "conversion_status": "CONVERTED_UNVERIFIED",
                    "artifacts": {}}
        self.native = {"assessment": {
            "id": "example", "version": 1,
            "variables": {"var-1": {"kind": "constant", "datatype": "string",
                                      "expression": {"literal": ["sample"]}}},
            "tests": {"test-1": {"capability": "variable.value",
                "variable": "var-1",
                "require": {"item_requirement": {
                    "items_found": "one_or_more", "items_satisfying": "every"}}}},
            "evaluate": {"test": "test-1"}
        }}
        self.trace = {"source_commit": PIN, "source_path": SOURCE_PATH,
                      "source_sha256": digest(XML), "definition_id": SOURCE_ID,
                      "test_bindings": [{"source_test": TEST_ID, "native_test": "test-1"}],
                      "native_identities": [{"kind": "variable",
                                             "source_id": "oval:example:var:1",
                                             "native_id": "var-1"}]}

    def publish(self, rows=None):
        directory = self.pack / "definitions" / slug(SOURCE_PATH) / slug(SOURCE_ID)
        directory.mkdir(parents=True, exist_ok=True)
        for filename, value in (("assessment.json", self.native),
                                ("source-trace.json", self.trace)):
            raw = (json.dumps(value, sort_keys=True) + "\n").encode()
            (directory / filename).write_bytes(raw)
            self.row["artifacts"][filename] = {"sha256": digest(raw), "bytes": len(raw)}
        (self.pack / "definitions.json").write_text(json.dumps(
            [self.row] if rows is None else rows))

    def inspect(self):
        return audit(self.src, self.pack, expected_xml=0,
                     expected_definitions=0, expected_tests=0)

    def test_one_to_one_structural_coverage_is_not_runtime_equivalence(self):
        self.publish()
        result = self.inspect()
        self.assertTrue(result["complete"], result["problems"])
        self.assertFalse(result["runtime_equivalence_proved"])
        self.assertEqual(result["coverage"]["pack"]["source_mapped_tests_checked"], 1)
        self.assertEqual(result["coverage"]["original"]["definitions"], 1)

    def test_missing_definition_is_explicit(self):
        self.publish(rows=[])
        result = self.inspect()
        self.assertFalse(result["source_accounted"])
        self.assertEqual(result["coverage"]["pack"]["source_definitions_without_disposition"], 1)

    def test_blocker_is_accounted_but_not_complete(self):
        self.row.update(conversion_status="blocked", diagnostic="unsupported source feature")
        self.publish()
        result = self.inspect()
        self.assertTrue(result["source_accounted"])
        self.assertFalse(result["complete"])
        self.assertEqual(result["coverage"]["pack"]["status_counts"]["blocked"], 1)

    def test_owner_approved_exclusion_is_not_conversion(self):
        self.row.update(conversion_status="intentionally_excluded",
                        diagnostic="platform not in approved SCAP-NG 0.4 collector scope",
                        owner_decision="issue-approval-reference")
        self.publish()
        result = self.inspect()
        self.assertTrue(result["scope_complete"], result["problems"])
        self.assertFalse(result["complete"])
        self.assertTrue(result["source_accounted"])

    def test_unapproved_exclusion_fails_closed(self):
        self.row.update(conversion_status="excluded",
                        diagnostic="unsupported platform")
        self.publish()
        result = self.inspect()
        self.assertFalse(result["scope_complete"])
        self.assertFalse(result["source_accounted"])
        self.assertIn("exclusion_without_owner_approval",
                      {p["type"] for p in result["problems"]})

    def test_corrupted_native_artifact_fails(self):
        self.publish()
        directory = self.pack / "definitions" / slug(SOURCE_PATH) / slug(SOURCE_ID)
        (directory / "assessment.json").write_text("{}")
        result = self.inspect()
        self.assertFalse(result["complete"])
        self.assertIn("converted_parity_failure",
                      {p["type"] for p in result["problems"]})

    def test_cardinality_regression_fails(self):
        # A State-free OVAL Test has no matching condition; existence still
        # governs its outcome and must match the original exactly.
        self.native["assessment"]["tests"]["test-1"]["require"][
            "item_requirement"]["items_found"] = "none"
        self.publish()
        result = self.inspect()
        self.assertFalse(result["complete"])
        self.assertIn("cardinality differs", str(result["problems"]))

    def test_variable_object_to_native_test_binding_mismatch(self):
        self.native["assessment"]["tests"]["test-1"]["variable"] = "wrong-var"
        self.publish()
        result = self.inspect()
        self.assertFalse(result["complete"])
        self.assertIn("variable_object Test binding differs", str(result["problems"]))

    def test_original_variable_value_mismatch_fails(self):
        self.native["assessment"]["variables"]["var-1"]["expression"]["literal"] = ["not-sample"]
        self.publish()
        result = self.inspect()
        self.assertFalse(result["complete"])
        self.assertIn("constant values", str(result["problems"]))

    def test_missing_source_variable_mapping_fails(self):
        self.trace["native_identities"] = []
        self.publish()
        result = self.inspect()
        self.assertFalse(result["complete"])
        self.assertIn("Variable Object-to-native capability mapping", str(result["problems"]))

    def test_changed_original_file_fails_closed(self):
        self.publish()
        (self.src / "agnostic" / "sample.xml").write_bytes(XML + b"\n")
        result = self.inspect()
        self.assertFalse(result["complete"])
        self.assertIn("source_sha256_mismatch",
                      {p["type"] for p in result["problems"]})

    def test_external_entities_are_rejected(self):
        self.publish()
        (self.src / "agnostic" / "evil.xml").write_text(
            '<!DOCTYPE oval_definitions [<!ENTITY a SYSTEM "file:///etc/passwd">]>'
            '<oval_definitions>&a;</oval_definitions>')
        with self.assertRaisesRegex(ValueError, "DTD"):
            sources(self.src)

    def test_original_evaluate_logic_not_replaced_by_or(self):
        self.native["assessment"]["evaluate"] = {
            "or": [{"test": "test-1"}, {"test": "test-1"}]}
        self.publish()
        result = self.inspect()
        self.assertFalse(result["complete"])
        self.assertIn("Evaluate logic mismatch", str(result["problems"]))

class DefinitionGraphTests(unittest.TestCase):
    def test_extended_oval_definitions_expand_into_the_same_native_ast(self):
        xml = b'''<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
          <definitions>
            <definition id="def-a"><criteria operator="AND">
              <criterion test_ref="test-one"/>
              <extend_definition definition_ref="def-b"/>
            </criteria></definition>
            <definition id="def-b"><criteria operator="OR">
              <criterion test_ref="test-two"/>
            </criteria></definition>
          </definitions>
          <tests>
            <variable_test id="test-one"/>
            <variable_test id="test-two"/>
          </tests>
        </oval_definitions>'''
        source = parse_oval(xml, SOURCE_PATH)
        self.assertEqual(reachable_source_tests(source, 'def-a'), {'test-one', 'test-two'})
        expected = ('and', (('test', 'test-one'), ('test', 'test-two')))
        self.assertEqual(normalize_source_evaluate(source, 'def-a'), expected)
        native = {"and": [{"test": "native-one"}, {"test": "native-two"}]}
        self.assertEqual(normalize_native_evaluate(
            native, {"native-one": "test-one", "native-two": "test-two"}), expected)

    def test_extended_definition_cycle_rejected(self):
        xml = b'''<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
          <definitions>
            <definition id="def-a"><criteria><extend_definition definition_ref="def-b"/></criteria></definition>
            <definition id="def-b"><criteria><extend_definition definition_ref="def-a"/></criteria></definition>
          </definitions></oval_definitions>'''
        source = parse_oval(xml, SOURCE_PATH)
        with self.assertRaisesRegex(ValueError, 'cyclic'):
            reachable_source_tests(source, 'def-a')


if __name__ == "__main__":
    unittest.main()
