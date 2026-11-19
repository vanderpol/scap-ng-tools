"""Pinned source-to-native disposition for OVAL variable_object Set/Filter forms."""
import json
import os
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/evidence/issue83/oval-variable-object-crosswalk.json"


class Issue83VariableObjectCrosswalkTests(unittest.TestCase):
    def test_receipt_is_pinned_and_has_no_implicit_runtime_claim(self):
        receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
        self.assertEqual(receipt["source"]["commit"],
                         "2f140ee5c5dd1ed9606fcd5afc301f6baeb48706")
        self.assertEqual(receipt["native"]["schema_commit"],
                         "5ee55288b369da26f308f40813e545b78dff2753")
        variants = {row["source_variant"]: row for row in receipt["crosswalk"]}
        self.assertEqual(variants["variable_object/set with dynamic variable or filter"]["native_status"],
                         "canonical_gap")
        self.assertEqual(variants["variable_object/set with dynamic variable or filter"]["converter_status"],
                         "held_fail_closed")
        self.assertEqual(variants["variable_object/set over constant variable_objects"]["converter_status"],
                         "bounded_native_recovery_only")
        self.assertFalse(receipt["claims"]["converter_source_parity"])
        self.assertFalse(receipt["claims"]["runtime_equivalence"])
        self.assertFalse(receipt["claims"]["silent_loss"])

    def test_xsd_digests_match_retained_pinned_checkout(self):
        import hashlib
        root = Path(os.environ.get("SCAP_NG_OVAL_SCHEMA_ROOT", ""))
        if not root.is_dir():
            self.skipTest("pinned OVAL schema checkout is unavailable")
        receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
        for name, row in receipt["source"]["schemas"].items():
            self.assertEqual(hashlib.sha256((root / name).read_bytes()).hexdigest(), row["sha256"])


if __name__ == "__main__":
    unittest.main()
