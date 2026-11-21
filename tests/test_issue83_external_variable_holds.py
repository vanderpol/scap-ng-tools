"""Focused source-evidence tests for external Variable hold auditing."""
from pathlib import Path
import json
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import audit_issue83_external_variable_holds as audit  # noqa: E402


class Issue83ExternalVariableHoldTests(unittest.TestCase):
    def test_joins_test_closure_to_restricted_external_variable(self):
        xml = """<oval:oval_definitions xmlns:oval="http://oval.mitre.org/XMLSchema/oval-definitions-5"
          xmlns:ind="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
          <oval:objects><ind:variable_object id="oval:test:obj:1"><oval:var_ref>oval:test:var:1</oval:var_ref></ind:variable_object></oval:objects>
          <oval:tests><ind:variable_test id="oval:test:tst:1" object_ref="oval:test:obj:1"/></oval:tests>
          <oval:variables><oval:external_variable id="oval:test:var:1" datatype="string">
            <oval:possible_restriction hint="phone"><oval:restriction operation="pattern match">^x$</oval:restriction></oval:possible_restriction>
          </oval:external_variable></oval:variables>
        </oval:oval_definitions>""".encode()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "source.xml").write_bytes(xml)
            receipt = root / "receipt.json"
            receipt.write_text(json.dumps({"tests": [{
                "source_file": "source.xml",
                "source_test_id": "oval:test:tst:1",
                "source_test_sha256": "witness",
                "failure_class": "canonical_input_constraint_hold",
                "diagnostic": "possible_restriction",
            }]}))
            report = audit.audit(root, receipt)
        self.assertEqual(report["summary"]["blocked_tests"], 1)
        self.assertEqual(report["summary"]["unique_external_variables"], 1)
        self.assertEqual(report["summary"]["possible_restrictions"], 1)
        variable = report["rows"][0]["variables"][0]
        self.assertEqual(variable["possible_restrictions"][0]["constraints"][0]["operation"],
                         "pattern match")
        self.assertEqual(variable["disposition"], "held_source_input_constraint")
        self.assertIsNone(variable["fixture"])

    def test_source_values_and_fixture_values_are_distinct_and_non_authoritative(self):
        source = """<oval:oval_definitions xmlns:oval="http://oval.mitre.org/XMLSchema/oval-definitions-5"
          xmlns:ind="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
          <oval:objects><ind:variable_object id="oval:test:obj:1"><oval:var_ref>oval:test:var:1</oval:var_ref></ind:variable_object></oval:objects>
          <oval:tests><ind:variable_test id="oval:test:tst:1" object_ref="oval:test:obj:1"/></oval:tests>
          <oval:variables><oval:external_variable id="oval:test:var:1" datatype="int">
            <oval:possible_value>0</oval:possible_value><oval:possible_value>1</oval:possible_value>
          </oval:external_variable></oval:variables>
        </oval:oval_definitions>""".encode()
        fixture = b"""<oval_variables xmlns="http://oval.mitre.org/XMLSchema/oval-variables-5">
          <variables><variable id="oval:test:var:1" datatype="int"><value>1</value><value>0</value></variable></variables>
        </oval_variables>"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "bundle.zip"
            with ZipFile(package, "w") as archive:
                archive.writestr("oval-def-ext.xml", source)
                archive.writestr("oval-def-ext_external-variables.xml", fixture)
            receipt = root / "receipt.json"
            receipt.write_text(json.dumps({"tests": [{
                "source_file": "bundle.zip!oval-def-ext.xml",
                "source_test_id": "oval:test:tst:1",
                "source_test_sha256": "witness",
                "failure_class": "canonical_input_constraint_hold",
                "diagnostic": "unbound external Variable",
            }]}))
            report = audit.audit(root, receipt)
        self.assertEqual(report["summary"]["possible_values"], 2)
        self.assertEqual(report["summary"]["dispositions"],
                         {"candidate_allowed_values_nonexecutable": 1})
        variable = report["rows"][0]["variables"][0]
        self.assertEqual(variable["datatype"], "int")
        self.assertEqual([item["value"] for item in variable["possible_values"]], ["0", "1"])
        self.assertEqual(variable["fixture"]["values"], ["1", "0"])
        self.assertFalse(variable["fixture"]["authoritative"])
        self.assertFalse(variable["candidate_native_input_executable"])


if __name__ == "__main__":
    unittest.main()
