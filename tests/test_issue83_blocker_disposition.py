"""Regression guard for the source-first 65-benchmark blocker ledger."""
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/evidence/issue85/full65-blocker-disposition-20261122.json"


class BlockerDispositionReceipt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipt = json.loads(RECEIPT.read_text())
        cls.rows = cls.receipt["blocked_rules"]

    def test_exact_scope_and_disposition_counts(self):
        self.assertEqual(len(self.rows), 94)
        self.assertEqual(self.receipt["scope"], {
            "blocked": 94,
            "converted": 6493,
            "converted_to_blocked": 0,
            "manual_only": 1403,
            "newly_converted_from_blocked": 14,
            "source_rules": 7990,
        })
        self.assertEqual(self.receipt["categories"], {
            "bounded_converter_gap": 2,
            "deprecated_source_construct": 83,
            "source-invalid-semantics": 9,
        })

    def test_deprecated_families_have_explicit_non_alias_disposition(self):
        deprecated = [row for row in self.rows
                      if row["disposition"] == "deprecated_source_construct"]
        self.assertEqual(len(deprecated), 83)
        messages = "\n".join(row["message"] for row in deprecated)
        self.assertEqual(messages.count("accesstoken_test"), 66)
        self.assertEqual(messages.count("user_test"), 5)
        concat = [row for row in deprecated
                  if "concat requires a scalar text operand" in row["message"]]
        self.assertEqual(len(concat), 12)
        for row in concat:
            self.assertIn("wmi_object", row["rationale"])
            self.assertIn("wmi57_object", row["rationale"])
            self.assertTrue(row["deprecated_source_objects"])
            self.assertTrue(all(object_id.startswith("oval:")
                                for object_id in row["deprecated_source_objects"]))

    def test_nondeprecated_holds_are_not_laundered(self):
        gaps = [row for row in self.rows
                if row["disposition"] == "canonical_language_gap"]
        self.assertEqual(len(gaps), 0)
        gaps = [row for row in self.rows
                if row["disposition"] == "bounded_converter_gap"]
        self.assertEqual(len(gaps), 2)
        self.assertTrue(all("dynamic Variable Object Set" in row["message"]
                            for row in gaps))
        invalid = [row for row in self.rows
                   if row["disposition"] == "source-invalid-semantics"]
        self.assertEqual(len(invalid), 9)
        self.assertEqual(sum("state capability mismatch" in row["message"]
                             for row in invalid), 7)
        self.assertEqual(sum("Variable cast" in row["message"] for row in invalid), 2)

    def test_every_row_retains_source_identity(self):
        for row in self.rows:
            with self.subTest(source_rule=row["source_rule"]):
                self.assertRegex(row["source_rule"], r"^xccdf_.+_rule$")
                self.assertRegex(row["source_rule_sha256"], r"^[0-9a-f]{64}$")
                self.assertTrue(row["benchmark"])
                self.assertTrue(row["rationale"])


if __name__ == "__main__":
    unittest.main()
