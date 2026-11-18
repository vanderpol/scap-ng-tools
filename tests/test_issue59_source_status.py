"""OVAL 5.12.3 normative-source classification must not fabricate conversion."""
import json
from pathlib import Path
import unittest

from scripts.build_issue59_source_status import build, classify, markdown, WINDOWS

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "docs/evidence/issue59"


class OVALSourceStatusTests(unittest.TestCase):
    def test_pinned_98_hold_crosswalk_has_exact_deprecated_source_types(self):
        historical = json.loads((EVIDENCE / "final-disposition-ledger.json").read_text())
        crosswalk = build(historical)
        summary = crosswalk["summary"]
        self.assertEqual(summary["historical_blocked_rules"], 98)
        self.assertEqual(summary["deprecated_by_pinned_oval"], 71)
        self.assertEqual(summary["needs_source_verification"], 27)
        self.assertEqual(summary["native_converted"], 0)
        self.assertFalse(summary["claim_of_nondeprecated_lossless_completion"])
        self.assertEqual(summary["deprecated_qname_counts"], {
            WINDOWS + "accesstoken_test": 66,
            WINDOWS + "user_test": 5,
        })
        self.assertEqual(len({(r["benchmark"], r["source_rule"])
                              for r in crosswalk["rows"]}), 98)
        self.assertTrue(all(r["native_conversion_disposition"] == "canonical_language_gap"
                            for r in crosswalk["rows"]))

    def test_absence_of_native_capability_never_implies_deprecation(self):
        template = {
            "benchmark": "fixture", "source_id": "fixture-rule",
            "blocker_group": "unsupported-capability",
            "disposition_class": "canonical_language_gap",
        }
        for diagnostic in (
            "unsupported test capability: " + WINDOWS + "userright_test",
            "unsupported test capability: " + WINDOWS + "user_sid55_test",
            "unsupported test capability: " + WINDOWS + "accesstoken_test-extra",
            "unrelated text containing accesstoken_test",
            "unsupported test capability: {other}accesstoken_test",
        ):
            with self.subTest(diagnostic=diagnostic):
                row = classify({**template, "diagnostic": diagnostic})
                self.assertEqual(row["source_normative_status"],
                                 "needs_source_verification")
                self.assertIsNone(row["deprecation_evidence"])
        for qname in ("accesstoken_test", "user_test"):
            row = classify({
                **template, "diagnostic": "unsupported test capability: "
                + WINDOWS + qname,
            })
            self.assertEqual(row["source_normative_status"],
                             "deprecated_by_pinned_oval")
            self.assertEqual(row["deprecation_evidence"]["deprecated_as_of"], "5.11")

    def test_committed_machine_and_human_report_are_reproducible(self):
        historical = json.loads((EVIDENCE / "final-disposition-ledger.json").read_text())
        expected = build(historical)
        committed = json.loads((EVIDENCE / "source-status-crosswalk.json").read_text())
        self.assertEqual(committed, expected)
        self.assertEqual((EVIDENCE / "SOURCE-SUPPORT-VS-CONVERSION.md").read_text(),
                         markdown(expected))


if __name__ == "__main__":
    unittest.main()
