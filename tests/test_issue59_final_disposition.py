"""Exact-head final disposition ledger checks for Issue #59."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "docs/evidence/issue59"


class FinalDispositionLedgerTests(unittest.TestCase):
    def test_all_source_ids_are_retained_and_categories_are_explicit(self):
        ledger = json.loads((EVIDENCE / "final-disposition-ledger.json").read_text())
        benchmark = ledger["benchmark"]
        standalone = ledger["standalone"]
        self.assertEqual(len(benchmark["rows"]), 98)
        self.assertEqual(len({(r["benchmark"], r["source_id"]) for r in benchmark["rows"]}), 98)
        self.assertTrue(benchmark["nonregression_pass"])
        self.assertEqual(benchmark["disposition_counts"], {
            "canonical_language_gap": 98,
            "deprecated": 0,
            "owner_excluded": 0,
            "recoverable_converter_defect": 0,
            "source_invalid": 0,
        })
        self.assertEqual(standalone["disposition_counts"], {
            "canonical_language_gap": 239,
            "deprecated": 19,
            "owner_excluded": 4,
            "recoverable_converter_defect": 0,
            "source_invalid": 25,
            "source_inventory_only": 1,
        })
        self.assertEqual(standalone["converted_parity_failures"], 0)
        self.assertTrue(ledger["policy"]["implicit_casts"] is False)
        self.assertTrue(ledger["policy"]["invented_equivalence"] is False)


if __name__ == "__main__":
    unittest.main()
