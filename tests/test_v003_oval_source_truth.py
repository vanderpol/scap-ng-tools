"""0.3 OVAL source truth vectors must survive the 0.4 converter transition."""
from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

from scripts.export_v003_oval_source_truth import build_vectors, original_oracle


class OriginalV003TruthContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = build_vectors()

    def test_all_legacy_truth_table_cases_accounted(self):
        data = self.data
        self.assertEqual(len(data["set_flag_cases"]), 3 * 6 * 6)
        self.assertEqual(len(data["filter_cases"]), 2 * 6)
        self.assertEqual(len(data["existence_cases"]), 5 * 8)
        self.assertEqual(len(data["boolean_operator_cases"]), 4 * 6 * 6)
        self.assertEqual(data["qualification"],
                         "OVAL_SOURCE_ONLY_NOT_NATIVE_OR_SCANNER_EQUIVALENCE")
        self.assertEqual(data["source"]["git_blob_sha1"],
                         "dcd513cb3c5d75a2ecab4fc2575a0adc3bf75915")

    def test_important_original_set_and_filter_status_edges(self):
        sets = {(x["source_operator"], x["first_flag"], x["second_flag"]):
                x["expected_flag"] for x in self.data["set_flag_cases"]}
        self.assertEqual(sets["UNION", "complete", "not_collected"], "incomplete")
        self.assertEqual(sets["INTERSECTION", "does_not_exist", "error"],
                         "does_not_exist")
        self.assertEqual(sets["COMPLEMENT", "complete", "not_applicable"], "error")
        filters = {(x["action"], x["state_result"]): x["expected"]
                   for x in self.data["filter_cases"]}
        self.assertTrue(filters["include", "true"])
        self.assertFalse(filters["exclude", "true"])
        self.assertTrue(filters["exclude", "false"])
        for result in ("error", "unknown", "not evaluated", "not applicable"):
            self.assertEqual(filters["include", result], "error")
            self.assertEqual(filters["exclude", result], "error")

    def test_legacy_existence_and_boolean_decisive_cases(self):
        populations = [(x["source_mode"], tuple(sorted(x["population"].items()))):
                       x["expected"] for x in self.data["existence_cases"]]
        zero = tuple(sorted({"exists": 0, "does_not_exist": 0,
                             "error": 0, "not_collected": 0}.items()))
        self.assertEqual(populations["none_exist", zero], "true")
        self.assertEqual(populations["at_least_one_exists", zero], "false")
        # OVAL any_exist is intentionally not the same as one_or_more.
        self.assertEqual(populations["any_exist", zero], "true")
        ops = {(x["operator"], tuple(x["operands"])): x["expected"]
               for x in self.data["boolean_operator_cases"]}
        self.assertEqual(ops["AND", ("false", "error")], "false")
        self.assertEqual(ops["OR", ("true", "error")], "true")
        self.assertEqual(ops["ONE", ("true", "true")], "false")
        self.assertEqual(ops["XOR", ("true", "true")], "false")

    def test_regeneration_is_deterministic(self):
        self.assertEqual(build_vectors(), self.data)
        self.assertEqual(original_oracle()["SET_FLAGS"],
                         ("error", "complete", "incomplete",
                          "does_not_exist", "not_collected", "not_applicable"))


if __name__ == "__main__":
    unittest.main()
