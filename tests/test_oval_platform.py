"""Production standalone unix.file conversion boundary tests."""
from hashlib import sha256
import json
import os
from pathlib import Path
import unittest
import yaml

from scap_ng_tools.contracts import FrozenSchemaSnapshot
from scap_ng_tools.converter import convert_oval_definition
from scap_ng_tools.converter.direct04 import validate_native_documents

PIN = "e3538595c5083b9c34d937a81d319234df9bbfaa"
FILE = "SCAP_1.4/OVAL_Test_Content/unix/unix-def_file_test.xml"
FILE_DEFINITION = "oval:navy.navwar.niwcatlantic.scc.test:def:1"
RPM_FILE = "SCAP_1.4/OVAL_Test_Content/linux/linux-def_rpmverifyfile_test.xml"


class StandaloneUnixFileConversion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schema = os.environ.get("SCAP_NG_SCHEMA_ROOT")
        corpus = os.environ.get("SCAP_NG_OVAL_TEST_CONTENT")
        if not schema or not corpus:
            raise unittest.SkipTest("SCAP_NG_SCHEMA_ROOT and SCAP_NG_OVAL_TEST_CONTENT required")
        cls.snapshot = FrozenSchemaSnapshot(schema)
        cls.corpus = Path(corpus)

    def source(self, relative):
        path = self.corpus / relative
        if not path.is_file():
            raise unittest.SkipTest(f"pinned platform source is not checked out: {relative}")
        return path

    def test_unix_file_definition_uses_production_adapter_and_preserves_bindings(self):
        source = self.source(FILE)
        raw = source.read_bytes()
        documents, trace = convert_oval_definition(
            schema_root=self.snapshot.schema_root, source=source,
            sha256_pin=sha256(raw).hexdigest(), definition_id=FILE_DEFINITION,
            source_commit=PIN, source_path=FILE)
        assessment = documents["assessment.json"]["assessment"]
        self.assertEqual(len(assessment["tests"]), 11)
        self.assertTrue(all(test["capability"] == "unix.file" for test in assessment["tests"].values()))
        self.assertEqual(len(trace["test_bindings"]), 11)
        self.assertTrue(trace["source_commit_blob_verified"])
        validate_native_documents(self.snapshot, documents)
        self.assertEqual(yaml.safe_load(yaml.safe_dump(documents["assessment.json"])), documents["assessment.json"])

    def test_mixed_platform_document_does_not_promote_unsupported_test(self):
        source = self.source(RPM_FILE)
        raw = source.read_bytes()
        with self.assertRaisesRegex(ValueError, "unsupported OVAL declaration kind/namespace"):
            convert_oval_definition(
                schema_root=self.snapshot.schema_root, source=source,
                sha256_pin=sha256(raw).hexdigest(),
                definition_id=FILE_DEFINITION, source_commit=PIN, source_path=RPM_FILE)
