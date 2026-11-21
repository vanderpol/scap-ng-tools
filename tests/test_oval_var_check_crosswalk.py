import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_oval_var_check_crosswalk as crosswalk  # noqa: E402


class OvalVarCheckCrosswalkTests(unittest.TestCase):
    def test_source_graph_rows_preserve_value_element_and_variable_cardinality(self):
        xml = b'''<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
          xmlns:ind="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
          <definitions><definition id="oval:test:def:1"><criteria>
            <criterion test_ref="oval:test:tst:1"/></criteria></definition></definitions>
          <tests><ind:variable_test id="oval:test:tst:1"><object object_ref="oval:test:obj:1"/><state state_ref="oval:test:ste:1"/></ind:variable_test></tests>
          <objects><ind:variable_object id="oval:test:obj:1"><var_ref>oval:test:var:1</var_ref></ind:variable_object></objects>
          <states><ind:variable_state id="oval:test:ste:1"><value var_ref="oval:test:var:1" var_check="none exist"/></ind:variable_state><ind:variable_state id="oval:test:ste:orphan"><value var_ref="oval:test:var:1" var_check="all"/></ind:variable_state></states>
          <variables><ind:constant_variable id="oval:test:var:1" datatype="string"><value>a</value><value>b</value></ind:constant_variable></variables>
        </oval_definitions>'''
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "witness.xml"
            path.write_bytes(xml)
            rows = crosswalk.rows_for_document(Path("agnostic/witness.xml"), xml, "source-pin")
        self.assertEqual(len(rows), 2)
        row = next(row for row in rows if not row["orphan_component"])
        self.assertEqual(row["test_id"], "oval:test:tst:1")
        self.assertEqual(row["definition_ids"], ["oval:test:def:1"])
        self.assertEqual(row["element"], "value")
        self.assertEqual(row["var_check"], "none exist")
        self.assertEqual(row["variable_value_count"], 2)
        self.assertEqual(row["native_value_match"], "none")
        self.assertEqual(row["native_disposition"], "admitted_value_match_crosswalk")
        orphan = next(row for row in rows if row["orphan_component"])
        self.assertIsNone(orphan["test_id"])
        self.assertEqual(orphan["component_id"], "oval:test:ste:orphan")

    def test_all_authored_matching_values_have_explicit_native_projection(self):
        self.assertEqual(set(crosswalk.MATCHING), {
            "all", "at least one", "none satisfy", "none exist", "only one"})
        self.assertEqual(crosswalk.MATCHING["all"], "every")
        self.assertEqual(crosswalk.MATCHING["only one"], "exactly_one")

    def test_receipt_is_deterministic(self):
        xml = b'''<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
          xmlns:ind="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"><tests>
          <ind:variable_test id="oval:test:tst:1"><value var_check="all"/></ind:variable_test>
          </tests></oval_definitions>'''
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "witness.xml"
            path.write_bytes(xml)
            first = crosswalk.rows_for_document(Path("agnostic/witness.xml"), xml, "source-pin")
            second = crosswalk.rows_for_document(Path("agnostic/witness.xml"), xml, "source-pin")
        self.assertEqual(first, second)

    def test_source_graph_follows_textual_set_and_filter_references(self):
        xml = b'''<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
          xmlns:ind="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
          <tests><ind:variable_test id="oval:test:tst:1"><object object_ref="oval:test:obj:1"/></ind:variable_test></tests>
          <objects><ind:variable_object id="oval:test:obj:1"><set><object_reference>oval:test:obj:2</object_reference><filter>oval:test:ste:1</filter></set></ind:variable_object><ind:variable_object id="oval:test:obj:2"><var_ref>oval:test:var:1</var_ref></ind:variable_object></objects>
          <states><ind:variable_state id="oval:test:ste:1"><value var_ref="oval:test:var:1" var_check="only one"/></ind:variable_state></states>
          <variables><ind:constant_variable id="oval:test:var:1" datatype="string"><value>a</value></ind:constant_variable></variables>
        </oval_definitions>'''
        rows = crosswalk.rows_for_document(Path("agnostic/witness.xml"), xml, "source-pin")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["component_id"], "oval:test:ste:1")
        self.assertFalse(rows[0]["orphan_component"])


if __name__ == "__main__":
    unittest.main()
