"""Acceptance receipt for the Object/State-authoritative blocker transition."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/evidence/issue83/cross-capability-reconciliation-20261122.json"


class CrossCapabilityReconciliationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))

    def test_only_matching_direct_pairs_are_recovered(self):
        recovered = {row["source_rule"] for row in self.receipt["recovered"]}
        self.assertEqual(len(recovered), 5)
        self.assertEqual(self.receipt["counts"]["remaining_blocked_rules"], 89)
        self.assertEqual(self.receipt["counts"]["remaining_by_root_cause"], {
            "deprecated_windows_accesstoken": 66,
            "deprecated_windows_user": 5,
            "deprecated_windows_wmi_transitive_concat": 12,
            "source_invalid_cross_capability_reference": 4,
            "source_invalid_variable_result_datatype": 2,
        })
        self.assertTrue(all(row["authority"] ==
                            "object_and_all_direct_state_capabilities_match"
                            for row in self.receipt["recovered"]))
        self.assertTrue(all(not row["runtime_qualified"]
                            for row in self.receipt["recovered"]))

    def test_remaining_source_invalid_and_deprecated_rows_are_source_linked(self):
        rows = self.receipt["remaining_rows"]
        self.assertEqual(len(rows), 89)
        self.assertEqual(len({row["source_rule"] for row in rows}), 89)
        self.assertEqual(sum(row["disposition"] == "deprecated-source" for row in rows), 83)
        self.assertEqual(sum(row["disposition"] == "source-invalid" for row in rows), 6)
        self.assertTrue(all(row["source_rule_sha256"] and row["source_zip_sha256"]
                            for row in rows))

    def test_contract_does_not_authorize_nested_filter_inference(self):
        excluded = self.receipt["recovery_contract"]["not_applied_to"]
        self.assertIn("nested Set/Filter States, which retain their own same-family validation",
                      excluded)
        self.assertFalse(self.receipt["recovery_contract"]["source_content_modified"])
        self.assertEqual(self.receipt["recovery_contract"]["runtime_equivalence"], "not_proved")


if __name__ == "__main__":
    unittest.main()
