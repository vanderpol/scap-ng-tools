"""Tests for the source/package platform accounting receipt."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_self_assertion_parity import PIN, PREFIX
from build_issue83_platform_receipt import build_receipt

XML = b'''<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
<generator/><definitions>
<definition id="oval:example:def:1"><criteria><criterion test_ref="oval:example:tst:1"/></criteria></definition>
<definition id="oval:example:def:2"><criteria><criterion test_ref="oval:example:tst:2"/></criteria></definition>
</definitions><tests>
<variable_test id="oval:example:tst:1" check_existence="at_least_one_exists"><object object_ref="oval:example:obj:1"/></variable_test>
<variable_test id="oval:example:tst:2" check_existence="at_least_one_exists"><object object_ref="oval:example:obj:2"/></variable_test>
</tests><objects>
<variable_object id="oval:example:obj:1"/><variable_object id="oval:example:obj:2"/>
</objects></oval_definitions>'''


class PlatformReceiptTests(unittest.TestCase):
    def make_package(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: None)
        source = root / "source" / "agnostic" / "sample.xml"
        source.parent.mkdir(parents=True)
        source.write_bytes(XML)
        package = root / "package"
        package.mkdir()
        readme = package / "README.md"
        readme.write_text("fixture\n")
        sha = hashlib.sha256(readme.read_bytes()).hexdigest()
        manifest = {
            "source_repository": "OVAL-Community/SCAP-Self-Assertion",
            "source_commit": PIN,
            "converter": "scap_ng_tools.converter.direct04",
            "schema": {"schema_version": "0.4.1", "canonical_commit": "schema", "aggregate_sha256": "s"},
            "artifacts": {"README.md": {"sha256": sha, "bytes": readme.stat().st_size}},
        }
        (package / "manifest.json").write_text(json.dumps(manifest))
        xml_sha = hashlib.sha256(XML).hexdigest()
        rows = []
        for definition_id, test_id, status, diagnostic in (
                ("oval:example:def:1", "oval:example:tst:1", "CONVERTED_UNVERIFIED", None),
                ("oval:example:def:2", "oval:example:tst:2", "blocked", "unsupported capability")):
            rows.append({"source_path": PREFIX + "agnostic/sample.xml", "source_sha256": xml_sha,
                         "definition_id": definition_id, "source_test_ids": [test_id],
                         "conversion_status": status, "diagnostic": diagnostic})
        (package / "definitions.json").write_text(json.dumps(rows))
        tests = []
        for definition_id, test_id, status, diagnostic in (
                ("oval:example:def:1", "oval:example:tst:1", "CONVERTED_UNVERIFIED", None),
                ("oval:example:def:2", "oval:example:tst:2", "blocked", "unsupported capability")):
            tests.append({"source_path": PREFIX + "agnostic/sample.xml", "source_sha256": xml_sha,
                          "test_id": test_id, "definition_ids": [definition_id],
                          "conversion_status": status, "diagnostic": diagnostic})
        (package / "tests.jsonl").write_text("\n".join(json.dumps(row) for row in tests) + "\n")
        return root, package, root / "source"

    def test_receipt_reconciles_source_and_groups_blockers(self):
        _, package, source = self.make_package()
        receipt = build_receipt(package, source_root=source, converter_commit="converter")
        self.assertTrue(receipt["qualification"]["source_identity_validated"])
        self.assertEqual(receipt["summary"], {
            "definitions": 2, "tests": 2,
            "converted_definitions": 1, "blocked_definitions": 1, "excluded_definitions": 0,
            "converted_tests": 1, "blocked_tests": 1, "excluded_tests": 0,
        })
        self.assertEqual(receipt["platforms"]["definitions"]["agnostic"]["blocked"], 1)
        self.assertEqual(receipt["blockers"]["tests"][0]["test_id"], "oval:example:tst:2")
        self.assertEqual(receipt["package"]["manifest_artifacts_verified"], 1)

    def test_manifest_artifact_cannot_escape_package(self):
        _, package, source = self.make_package()
        manifest = json.loads((package / "manifest.json").read_text())
        metadata = manifest["artifacts"]["README.md"]
        manifest["artifacts"] = {"../outside": metadata}
        (package / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "escapes package"):
            build_receipt(package, source_root=source, converter_commit="converter")

    def test_receipt_fails_on_source_hash_mismatch(self):
        _, package, source = self.make_package()
        definitions = json.loads((package / "definitions.json").read_text())
        definitions[0]["source_sha256"] = "0" * 64
        (package / "definitions.json").write_text(json.dumps(definitions))
        with self.assertRaisesRegex(ValueError, "source identity mismatch"):
            build_receipt(package, source_root=source, converter_commit="converter")


if __name__ == "__main__":
    unittest.main()
