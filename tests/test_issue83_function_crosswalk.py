"""Keep the normative OVAL FunctionGroup crosswalk explicit and source-first."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class OVALFunctionCrosswalk(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipt = json.loads((ROOT / "docs/evidence/issue83/oval-function-crosswalk.json").read_text())
        cls.rows = {row["name"]: row for row in cls.receipt["crosswalk"]}

    def test_all_pinned_function_group_declarations_are_dispositioned(self):
        expected = {
            "arithmetic", "begin", "concat", "end", "escape_regex", "split",
            "substring", "time_difference", "regex_capture", "unique", "count",
            "merge", "glob_to_regex",
        }
        self.assertEqual(set(self.rows), expected)
        for name, row in self.rows.items():
            with self.subTest(name=name):
                self.assertTrue(row["source_xsd_line"] > 0)
                self.assertIn(row["native_status"], {
                    "representable", "canonical_gap_for_dynamic_expression",
                })
                self.assertIn(row["runtime_status"], {"unproved", "not_reached"})

    def test_dynamic_literal_functions_are_explicit_canonical_holds(self):
        for name in ("escape_regex", "glob_to_regex"):
            self.assertIsNone(self.receipt["native"]["expression_pointer_by_name"][name])
            self.assertEqual(self.rows[name]["native_status"],
                             "canonical_gap_for_dynamic_expression")
            self.assertEqual(self.rows[name]["converter_status"],
                             "implemented_static_literal_only")
        self.assertEqual(self.receipt["holds"][0]["category"], "canonical_gap")

    def test_concat_receipt_points_to_focused_evidence(self):
        self.assertEqual(self.rows["concat"]["converter_status"],
                         "implemented_generic_collection_text_boundary")
        self.assertEqual(self.receipt["source"]["commit"],
                         "2f140ee5c5dd1ed9606fcd5afc301f6baeb48706")


if __name__ == "__main__":
    unittest.main()
