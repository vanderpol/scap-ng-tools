"""Integrity checks for compact, source-linked correction receipts."""
from __future__ import annotations

import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class SourceCorrectionReceiptTests(unittest.TestCase):
    def load(self, name: str) -> dict:
        path = ROOT / "docs" / "evidence" / "issue83" / name
        with path.open(encoding="utf-8") as stream:
            return json.load(stream)

    def test_nvram_pr19_receipt_preserves_identity_and_native_parity(self):
        receipt = self.load("nvram-pr19-focused-qualification.json")
        source = receipt["source"]
        conversion = receipt["conversion"]

        self.assertEqual(receipt["format"], "scap-ng-tools/issue83-source-correction-focused/1")
        self.assertEqual(source["repository"], "OVAL-Community/SCAP-Self-Assertion")
        self.assertEqual(source["path"], "SCAP_1.4/OVAL_Test_Content/macos/macos-def_nvram512_test.xml")
        self.assertEqual(source["definition_id"], "oval:org.mitre.oval.test:def:448")
        self.assertEqual(source["corrected_pr"], 19)
        self.assertTrue(source["source_commit_blob_verified"])
        self.assertTrue(conversion["base_schema_validated"])
        self.assertTrue(conversion["corrected_schema_validated"])
        self.assertTrue(conversion["native_assessment_bytes_identical"])
        self.assertTrue(conversion["source_trace_differs_as_expected"])
        self.assertEqual(conversion["independent_runtime_equivalence"], "not_proved")

        for key in ("base_sha256", "corrected_sha256"):
            self.assertRegex(source[key], HEX64)
        self.assertRegex(conversion["base_assessment_sha256"], HEX64)
        self.assertEqual(
            conversion["base_assessment_sha256"],
            conversion["corrected_assessment_sha256"],
        )
        self.assertEqual(
            len(source["affected_test_ids"]), 3,
        )
        self.assertIn("oval:org.mitre.oval.test:obj:754", source["affected_objects"])
        self.assertEqual(len(source["affected_states"]), 3)

    def test_windows_policy_pr5_receipt_distinguishes_source_hold_and_recovery(self):
        receipt = self.load("windows-policy-pr5-focused-qualification.json")
        source = receipt["source"]
        conversion = receipt["conversion"]
        self.assertEqual(source["pull_request"], 5)
        self.assertEqual(source["classification"], "source_typed_literal_invalid")
        self.assertTrue(source["source_commit_fetch_verified"])
        self.assertIn("0", source["files"][1]["correction"])
        self.assertNotIn("86400", source["files"][1]["correction"])
        self.assertEqual(len(source["files"]), 2)
        self.assertEqual(len(conversion["cases"]), 2)
        for case in conversion["cases"]:
            self.assertEqual(case["base_status"], "blocked")
            self.assertEqual(case["corrected_status"], "CONVERTED_UNVERIFIED")
            self.assertTrue(case["corrected_schema_validated"])
            self.assertRegex(case["corrected_assessment_sha256"], HEX64)
        self.assertEqual(conversion["independent_runtime_equivalence"], "not_proved")

    def test_committed_receipt_is_compact_and_does_not_embed_source_or_host_data(self):
        path = ROOT / "docs" / "evidence" / "issue83" / "nvram-pr19-focused-qualification.json"
        receipt = self.load("nvram-pr19-focused-qualification.json")
        self.assertLess(path.stat().st_size, 16 * 1024)
        self.assertEqual(receipt["reproduction"]["evidence_root"], "<fresh-external-temp-directory>")
        self.assertEqual(receipt["reproduction"]["generated_evidence_commit"], "not committed; compact hashes only")
        self.assertNotIn("<nvram512_object", path.read_text(encoding="utf-8"))
        self.assertIn("0a1ee9365aff7962118f316ed9df822217bbf850", receipt["reproduction"]["source_fetch"])


if __name__ == "__main__":
    unittest.main()
