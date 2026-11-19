"""Focused tests for source-witness converter qualification classification."""
from pathlib import Path
import os
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

    def test_schema_preflight_rejects_noncanonical_commit(self):
        with self.assertRaises(ValueError):
            qualification.verify_schema_root(Path("/does/not/exist"), "old-pin")

    @unittest.skipUnless(os.environ.get("SCAP_NG_SCHEMA_ROOT"),
                         "set SCAP_NG_SCHEMA_ROOT for exact schema preflight")
    def test_schema_preflight_verifies_exact_active_family(self):
        root, digest = qualification.verify_schema_root(
            Path(os.environ["SCAP_NG_SCHEMA_ROOT"]), qualification.CANONICAL_COMMIT)
        self.assertTrue(root.is_dir())
        self.assertEqual(digest, qualification.FLAT_SCHEMA_SHA256)

    def test_unknown_failure_remains_converter_failure(self):
        self.assertEqual(qualification.classify("unexpected internal diagnostic"),
                         "converter_failure")


if __name__ == "__main__":
    unittest.main()
