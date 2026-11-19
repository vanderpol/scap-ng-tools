"""Focused tests for source-witness converter qualification classification."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import qualify_issue83_witness_conversion as qualification  # noqa: E402


class Issue83WitnessConversionTests(unittest.TestCase):
    def test_classifies_known_source_and_canonical_holds(self):
        self.assertEqual(
            qualification.classify("unbound external Variable or unsupported possible_restriction"),
            "canonical_input_constraint_hold")
        self.assertEqual(
            qualification.classify("invalid int literal: 'abc'"),
            "source_typed_literal_invalid")

    def test_unknown_failure_remains_converter_failure(self):
        self.assertEqual(qualification.classify("unexpected internal diagnostic"),
                         "converter_failure")


if __name__ == "__main__":
    unittest.main()
