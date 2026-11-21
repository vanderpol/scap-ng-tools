import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CorrectedSourceQualificationReceiptTests(unittest.TestCase):
    def test_corrected_source_receipt_keeps_denominators_and_proof_boundaries(self):
        receipt = json.loads((ROOT / "docs/evidence/issue88/corrected-source-qualification-53c.json").read_text())
        self.assertEqual(receipt["source"]["commit"], "53c18ea31a1976209572ec8b068e1a02be588456")
        self.assertEqual(receipt["source"]["historical_baseline"], "e3538595c5083b9c34d937a81d319234df9bbfaa")
        standalone = receipt["standalone"]
        self.assertEqual((standalone["definitions"], standalone["tests"]), (167, 799))
        self.assertEqual((standalone["converted_definitions"], standalone["blocked_definitions"]), (117, 50))
        self.assertEqual((standalone["converted_tests"], standalone["blocked_tests"]), (678, 121))
        self.assertTrue(standalone["source_accounted"])
        self.assertFalse(standalone["structural_complete"])
        self.assertEqual(receipt["source_validation"]["xsd"]["valid"], 143)
        self.assertEqual(receipt["source_validation"]["schematron"]["files_with_reports"], 1)
        benchmark = receipt["benchmarks"]
        self.assertEqual(benchmark["benchmarks"], 65)
        self.assertEqual(benchmark["candidate"], {"blocked": 95, "converted": 6492, "manual_only": 1403})
        self.assertEqual(benchmark["newly_converted_from_blocked"], 13)
        self.assertEqual(benchmark["newly_blocked_from_converted"], 0)
        self.assertTrue(benchmark["nonregression_pass"])
        self.assertEqual(receipt["proof_boundaries"]["runtime_execution"], "not_run")
        self.assertEqual(receipt["proof_boundaries"]["independent_oval_equivalence"], "not_proved")


if __name__ == "__main__":
    unittest.main()
