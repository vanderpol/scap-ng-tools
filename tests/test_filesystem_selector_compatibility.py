"""Issue #14 filesystem selector emission against the accepted flat schema."""
import os
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

import yaml

from scap_ng_tools.contracts import FrozenSchemaSnapshot
from scap_ng_tools.converter.direct04 import load_runtime, validate_native_documents


ROOT = Path(__file__).resolve().parents[1]
XSI_NIL = "{http://www.w3.org/2001/XMLSchema-instance}nil"


class FilesystemSelectorCompatibilityTests(unittest.TestCase):
    """Exercise the actual Object visitor, YAML serializer, and schema gate."""

    @classmethod
    def setUpClass(cls):
        schema_root = os.environ.get("SCAP_NG_SCHEMA_ROOT")
        if not schema_root:
            raise unittest.SkipTest("Set SCAP_NG_SCHEMA_ROOT to the accepted SCAP-NG checkout")
        cls.snapshot = FrozenSchemaSnapshot(schema_root)
        cls.engine = load_runtime()
        cls.capabilities = (
            "unix.file",
            "windows.file",
            "windows.fileeffectiverights",
        )
        cls.mappings = cls.snapshot.supported_mappings(cls.capabilities)

    @staticmethod
    def _document(capability, native_object):
        return {
            "assessment": {
                "id": "issue14-filesystem-selector-assessment",
                "version": 1,
                "assessment_title": "Issue #14 filesystem selector compatibility",
                "mode": "automated",
                "class": "compliance",
                "specification": {
                    "id": "scap-ng.pre-alpha.assessment",
                    "version": "0.4.0",
                },
                "tests": {
                    "filesystem-selector-test": {
                        "test_title": "Filesystem selector compatibility",
                        "capability": capability,
                        "object": native_object,
                        "require": {
                            "item_requirement": {"items_found": "one_or_more"},
                        },
                        "reported_elements": "all",
                    },
                },
                "evaluate": {"test": "filesystem-selector-test"},
            },
        }

    def _convert(self, capability, selectors):
        mapping = next(item for item in self.mappings if item["capability"] == capability)
        namespace = mapping["source"]["namespace"]
        object_element = ET.Element(
            "{" + namespace + "}" + mapping["source"]["object"],
            {"id": "issue14-filesystem-object"},
        )
        for field, attributes, text in selectors:
            child = ET.SubElement(object_element, "{" + namespace + "}" + field, attributes)
            child.text = text
        converter = self.engine.AssessmentConverter(
            object(), "issue14-component", [mapping]
        )
        converter.object_uses = {"issue14-filesystem-object": 1}
        native_object = converter.convert_object(object_element)
        document = self._document(capability, native_object)
        validate_native_documents(self.snapshot, {"assessment": document})

        from v04_direct_yaml import authoring_yaml
        yaml_text = authoring_yaml(document)
        roundtrip = yaml.safe_load(yaml_text)
        validate_native_documents(self.snapshot, {"assessment-yaml": roundtrip})
        self.assertEqual(roundtrip, document)
        self.assertEqual(native_object.get("filesystem"), "all")
        self.assertNotIn("full_path", native_object)
        self.assertNotIn("directory", native_object)
        self.assertNotIn("name", native_object)
        return native_object

    def test_all_nine_selector_contracts_emit_schema_valid_candidate_a_yaml(self):
        for capability in self.capabilities:
            with self.subTest(capability=capability):
                trustee = (
                    [("trustee_sid", {"operation": "equals"}, "S-1-5-18")]
                    if capability == "windows.fileeffectiverights" else []
                )
                filepath = self._convert(
                    capability,
                    [("filepath", {"operation": "equals"}, "/etc/ssh/sshd_config"), *trustee],
                )
                self.assertEqual(set(filepath) & {"filepath", "path", "filename"}, {"filepath"})

                path = self._convert(
                    capability,
                    [
                        ("path", {"operation": "pattern match"}, r"/etc/ssh"),
                        ("filename", {"operation": "case insensitive equals"}, "sshd_config"),
                        *trustee,
                    ],
                )
                self.assertEqual(
                    set(path) & {"filepath", "path", "filename"},
                    {"path", "filename"},
                )
                self.assertEqual(path["path"], {"matches_regex": r"/etc/ssh"})

                filename = self._convert(
                    capability,
                    [
                        ("path", {"operation": "equals"}, "/etc/ssh"),
                        ("filename", {"operation": "equals"}, "sshd_config"),
                        *trustee,
                    ],
                )
                self.assertIn("filename", filename)

    def test_windows_pattern_path_recursion_guard_uses_canonical_selector_map(self):
        mapping = next(item for item in self.mappings if item["capability"] == "windows.file")
        namespace = mapping["source"]["namespace"]
        object_element = ET.Element(
            "{" + namespace + "}" + mapping["source"]["object"],
            {"id": "issue22-pattern-path-object"},
        )
        ET.SubElement(object_element, "{" + namespace + "}path", {
            "operation": "pattern match",
        }).text = r"C:\ProgramData"
        ET.SubElement(object_element, "{" + namespace + "}filename", {
            "operation": "equals",
        }).text = "sshd_config"
        ET.SubElement(object_element, "{" + namespace + "}behaviors", {
            "max_depth": "1", "recurse_direction": "down",
        })
        converter = self.engine.AssessmentConverter(object(), "issue22-component", [mapping])
        converter.object_uses = {"issue22-pattern-path-object": 1}
        with self.assertRaisesRegex(ValueError, "pattern-path recursion"):
            converter.convert_object(object_element)

    def test_nullable_filename_preserves_directory_selection(self):
        for capability in self.capabilities:
            with self.subTest(capability=capability):
                trustee = (
                    [("trustee_sid", {"operation": "equals"}, "S-1-5-18")]
                    if capability == "windows.fileeffectiverights" else []
                )
                native = self._convert(
                    capability,
                    [
                        ("path", {"operation": "equals"}, "/etc/ssh"),
                        ("filename", {XSI_NIL: "true"}, None),
                        *trustee,
                    ],
                )
                self.assertIsNone(native["filename"])


if __name__ == "__main__":
    unittest.main()
