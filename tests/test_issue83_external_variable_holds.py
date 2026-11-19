"""Focused source-evidence tests for external Variable hold auditing."""
from pathlib import Path
import json
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

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
        self.assertEqual(variable["possible_restrictions"][0]["operation"], "pattern match")


if __name__ == "__main__":
    unittest.main()
