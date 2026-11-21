"""Regression proof for the reviewed Solaris package511 source correction."""
from __future__ import annotations

import json
import re
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class SolarisPackage511ReceiptTests(unittest.TestCase):
    def test_source_correction_and_requalification_are_source_traced(self):
        receipt = json.loads(
            (ROOT / "docs/evidence/issue88/post-solaris-package511-qualification.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(receipt["source"]["corrected_commit"],
                         "d91e6ba33841e3202dc27d3e0d469a7abd939b16")
        self.assertEqual(receipt["source"]["changed_file_count"], 1)
        self.assertEqual(receipt["source"]["changed_files"], [
            "SCAP_1.4/OVAL_Test_Content/solaris/sol-def_package511_test.xml",
        ])
        self.assertRegex(receipt["source"]["original_file_sha256"], HEX64)
        self.assertRegex(receipt["source"]["corrected_file_sha256"], HEX64)
        self.assertEqual(receipt["source_validation"]["xsd_valid_files"], 143)
        self.assertEqual(receipt["source_validation"]["schematron_clean_files"], 143)
        self.assertEqual(receipt["source_validation"]["schematron_reports"], 0)

        focused = receipt["focused_conversion"]
        self.assertEqual(focused["focused_before"]["blocked_definitions"], 1)
        self.assertEqual(focused["focused_after"]["blocked_definitions"], 0)
        self.assertEqual(focused["focused_before"]["blocked_tests"], 6)
        self.assertEqual(focused["focused_after"]["blocked_tests"], 0)
        self.assertTrue(focused["native_assessment_common_bytes_unchanged"])
        self.assertEqual(len(focused["source_test_ids"]), 6)
        self.assertTrue(all(test_id.endswith(tuple(f":tst:{i}" for i in range(1, 7)))
                            for test_id in focused["source_test_ids"]))

        full = receipt["full_qualification"]
        self.assertTrue(full["source_accounted"])
        self.assertFalse(full["structural_complete"])
        self.assertEqual((full["definitions_converted"], full["definitions_blocked"]), (166, 1))
        self.assertEqual((full["tests_converted"], full["tests_blocked"]), (781, 18))
        self.assertEqual(full["remaining_definition_holds"][0]["id"],
                         "oval:org.mitre.oval.test:def:562")
        self.assertEqual(full["remaining_definition_holds"][1]["id"],
                         "oval:navy.navwar.niwcatlantic.scc.test:def:1")

        benchmark = receipt["benchmark_qualification"]
        self.assertEqual(benchmark["result"], {
            "candidate": {"blocked": 95, "converted": 6492, "manual_only": 1403},
            "original": {"blocked": 108, "converted": 6479, "manual_only": 1403},
            "newly_blocked_from_converted": 0,
            "newly_converted_from_blocked": 13,
            "nonregression_pass": True,
        })
        self.assertEqual(receipt["proof_boundaries"]["runtime_execution"], "not_run")
        self.assertEqual(receipt["proof_boundaries"]["independent_oval_equivalence"], "not_proved")


if __name__ == "__main__":
    unittest.main()
