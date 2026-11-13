"""Accounting checks for the pinned independent/UNIX/Linux source sweep."""
from collections import Counter
import json
from hashlib import sha256
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "docs/evidence/issue37-platform-corpus"


class PlatformSelfAssertionCorpus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not PACK.is_dir():
            raise unittest.SkipTest("platform corpus evidence pack is not checked out")
        cls.manifest = json.loads((PACK / "manifest.json").read_text())
        cls.definitions = json.loads((PACK / "definitions.json").read_text())
        cls.tests = [json.loads(line) for line in (PACK / "tests.jsonl").read_text().splitlines()]

    def test_complete_platform_denominator_and_agnostic_recovery(self):
        self.assertEqual(self.manifest["source_roots"], [
            "SCAP_1.4/OVAL_Test_Content/agnostic",
            "SCAP_1.4/OVAL_Test_Content/unix",
            "SCAP_1.4/OVAL_Test_Content/linux",
        ])
        self.assertEqual(self.manifest["summary"], {
            "definitions": 76, "tests": 462,
            "converted_definitions": 7, "blocked_definitions": 69,
            "schema_valid_yaml_documents": 7, "converted_tests": 58,
            "blocked_tests": 404, "execution": "not_run",
        })
        self.assertEqual(Counter(Path(row["source_path"]).parts[2] for row in self.definitions),
                         Counter({"agnostic": 47, "unix": 13, "linux": 16}))
        self.assertEqual(Counter(Path(row["source_path"]).parts[2] for row in self.tests),
                         Counter({"agnostic": 328, "unix": 72, "linux": 62}))

    def test_platform_ledger_retains_features_diagnostics_and_integrity(self):
        self.assertEqual(len(self.manifest["feature_inventory"]["blocked_test_feature_counts"]),
                         len(set(feature for row in self.tests if row["conversion_status"] == "blocked"
                                   for feature in row["feature_categories"])))
        self.assertEqual(self.manifest["feature_inventory"]["blocked_test_feature_counts"]["source_family:unix"], 72)
        self.assertEqual(self.manifest["feature_inventory"]["blocked_test_feature_counts"]["source_family:linux"], 62)
        self.assertTrue(all(row.get("diagnostic") for row in self.tests
                            if row["conversion_status"] == "blocked"))
        self.assertTrue(all("expected_outcome" not in row for row in self.definitions + self.tests))
        for relative, integrity in self.manifest["artifacts"].items():
            raw = (PACK / relative).read_bytes()
            self.assertEqual(len(raw), integrity["bytes"], relative)
            self.assertEqual(sha256(raw).hexdigest(), integrity["sha256"], relative)
