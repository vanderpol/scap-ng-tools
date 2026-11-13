"""Integrity and accounting checks for the pinned agnostic conversion pack."""
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

from scap_ng_tools.contracts import FrozenSchemaSnapshot
from scap_ng_tools.converter.direct04 import validate_native_documents

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "docs/evidence/issue37-full-corpus"


class FullSelfAssertionCorpus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not PACK.is_dir():
            raise unittest.SkipTest("full corpus evidence pack is not checked out")
        cls.manifest = json.loads((PACK / "manifest.json").read_text())
        cls.definitions = json.loads((PACK / "definitions.json").read_text())
        cls.tests = [json.loads(line) for line in (PACK / "tests.jsonl").read_text().splitlines()]

    def test_pinned_denominator_and_conversion_counts(self):
        self.assertEqual(self.manifest["source_commit"],
                         "e3538595c5083b9c34d937a81d319234df9bbfaa")
        self.assertEqual(self.manifest["summary"], {
            "definitions": 47, "tests": 328,
            "converted_definitions": 7, "blocked_definitions": 40,
            "schema_valid_yaml_documents": 7, "converted_tests": 58,
            "blocked_tests": 270, "execution": "not_run",
        })
        self.assertEqual(len(self.definitions), 47)
        self.assertEqual(len(self.tests), 328)

    def test_every_published_file_matches_manifest(self):
        listed = set(self.manifest["artifacts"])
        actual = {path.relative_to(PACK).as_posix() for path in PACK.rglob("*")
                  if path.is_file() and path.name != "manifest.json"}
        self.assertEqual(actual, listed)
        for relative, integrity in self.manifest["artifacts"].items():
            raw = (PACK / relative).read_bytes()
            self.assertEqual(len(raw), integrity["bytes"], relative)
            self.assertEqual(sha256(raw).hexdigest(), integrity["sha256"], relative)

    def test_native_pairs_are_equal_and_have_no_invented_outcomes(self):
        snapshot_root = __import__("os").environ.get("SCAP_NG_SCHEMA_ROOT")
        snapshot = FrozenSchemaSnapshot(snapshot_root) if snapshot_root else None
        converted = [row for row in self.definitions
                     if row["conversion_status"] == "CONVERTED_UNVERIFIED"]
        self.assertEqual(len(converted), 7)
        for row in converted:
            directory = PACK / "definitions" / row["source_path"].replace(":", "_").replace("/", "_") / row["definition_id"].replace(":", "_").replace("/", "_")
            document = json.loads((directory / "assessment.json").read_text())
            self.assertEqual(yaml.safe_load((directory / "assessment.yaml").read_text()), document)
            self.assertFalse(any("expected_outcome" in item for item in self.tests))
            if snapshot:
                validate_native_documents(snapshot, {"assessment.json": document})
        for row in self.definitions + self.tests:
            self.assertNotIn("expected_outcome", row)

    def test_owner_lists_are_deduplicated_and_shared_tests_preserved(self):
        for row in self.definitions:
            self.assertEqual(row["source_test_ids"], list(dict.fromkeys(row["source_test_ids"])))
        shared = [row for row in self.tests if len(row["definition_ids"]) > 1]
        self.assertEqual(len(shared), 3)
        self.assertTrue(all(row["definition_ids"] == list(dict.fromkeys(row["definition_ids"]))
                           for row in shared))
        self.assertEqual(len(json.loads((PACK / "source-mappings.json").read_text())), 7)

    def test_blocked_ledger_retains_exact_converter_diagnostics(self):
        blocked = [row for row in self.definitions if row["conversion_status"] == "blocked"]
        self.assertEqual(len(blocked), 40)
        self.assertEqual(Counter(row["diagnostic"] for row in blocked), Counter({
            "standalone functions, Object components and external Variables remain held": 13,
            "standalone Variable datatype held: boolean": 10,
            "standalone Variable datatype held: binary": 7,
            "unsupported OVAL declaration kind/namespace": 2,
            "standalone Variable Object Sets/Filters held": 2,
            "standalone Variable datatype held: evr_string": 1,
            "standalone Variable datatype held: float": 1,
            "standalone Variable datatype held: ipv4_address": 1,
            "standalone Variable datatype held: ipv6_address": 1,
            "standalone Variable datatype held: version": 1,
            "standalone source must declare OVAL 5.12.3": 1,
        }))
        blocked_tests = [row for row in self.tests if row["conversion_status"] == "blocked"]
        self.assertEqual(len(blocked_tests), 270)
        self.assertTrue(all(row["diagnostic"] for row in blocked_tests))

    def test_combined_blocker_is_split_by_source_features(self):
        self.assertIn("source-graph labels only", self.manifest["feature_inventory"]["policy"])
        combined = [row for row in self.definitions
                    if row["diagnostic"] ==
                    "standalone functions, Object components and external Variables remain held"]
        self.assertEqual(len(combined), 13)
        self.assertTrue(any("functions" in row["feature_categories"] for row in combined))
        self.assertTrue(any("object_components" in row["feature_categories"] for row in combined))
        self.assertTrue(all("source_family:agnostic" in row["feature_categories"] for row in combined))
        self.assertEqual(
            self.manifest["feature_inventory"]["blocked_definition_feature_counts"]["functions"], 10)

    def test_tampered_published_output_is_rejected(self):
        snapshot_root = os.environ.get("SCAP_NG_SCHEMA_ROOT")
        if not snapshot_root:
            self.skipTest("SCAP_NG_SCHEMA_ROOT required for schema mutation check")
        snapshot = FrozenSchemaSnapshot(snapshot_root)
        row = next(item for item in self.definitions
                   if item["conversion_status"] == "CONVERTED_UNVERIFIED")
        directory = PACK / "definitions" / row["source_path"].replace(":", "_").replace("/", "_") / row["definition_id"].replace(":", "_").replace("/", "_")
        document = json.loads((directory / "assessment.json").read_text())
        document["assessment"].pop("version")
        with self.assertRaises(ValueError):
            validate_native_documents(snapshot, {"assessment.json": document})

    def test_tampered_source_is_rejected_by_production_cli(self):
        snapshot_root = os.environ.get("SCAP_NG_SCHEMA_ROOT")
        corpus = os.environ.get("SCAP_NG_OVAL_TEST_CONTENT")
        if not snapshot_root or not corpus:
            self.skipTest("pinned source and schema roots required for source mutation check")
        source = Path(corpus) / "SCAP_1.4/OVAL_Test_Content/agnostic/oval-def_constant_variable.xml"
        original = source.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            mutated = Path(directory) / source.name
            mutated.write_bytes(original + b"\n")
            output = Path(directory) / "output"
            command = [sys.executable, "-m", "scap_ng_tools.converter.direct04",
                       "--schema-root", snapshot_root, "--source", str(mutated),
                       "--sha256", sha256(original).hexdigest(),
                       "--oval-definition", "oval:org.mitre.oval.test:def:92",
                       "--source-commit", "e3538595c5083b9c34d937a81d319234df9bbfaa",
                       "--source-path", "SCAP_1.4/OVAL_Test_Content/agnostic/oval-def_constant_variable.xml",
                       "--output", str(output)]
            process = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn("SHA-256", process.stderr)
            self.assertFalse(output.exists())
