"""OVAL 5.12.3 SID behavior crosswalk regression tests.

The OVAL names ``include_group`` and ``resolve_group`` are reused by several
Windows behavior types.  Deprecation is declaration-specific: the pinned
schema deprecates them on AccesstokenBehaviors and several effective-rights
behavior types, but not on SidBehaviors or SidSidBehaviors.  These tests keep
that distinction from regressing into a name-only source hold.
"""
import os
import unittest
import xml.etree.ElementTree as ET

from scap_ng_tools.converter.direct04 import load_pinned_snapshot, load_runtime


WINDOWS = "http://oval.mitre.org/XMLSchema/oval-definitions-5#windows"


@unittest.skipUnless(os.environ.get("SCAP_NG_SCHEMA_ROOT"),
                     "set SCAP_NG_SCHEMA_ROOT for the pinned 0.4.1 crosswalk")
class WindowsSIDBehaviorCrosswalkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = load_runtime()
        snapshot = load_pinned_snapshot(os.environ["SCAP_NG_SCHEMA_ROOT"])
        cls.mappings = snapshot.supported_mappings(cls.engine.CAPABILITIES)

    def convert_object(self, local_name, attributes=None):
        attributes = attributes or {}
        serialized = " ".join(f'{name}="{value}"'
                              for name, value in attributes.items())
        behavior = (f'<w:behaviors {serialized}/>' if serialized
                    else '<w:behaviors/>')
        element = ET.fromstring(
            f'<w:{local_name} xmlns:w="{WINDOWS}" id="obj-1">'
            f'{behavior}</w:{local_name}>')
        visitor = self.engine.AssessmentConverter(
            None, None, self.mappings, human_compact=False, native_recovery=True)
        # convert_object uses this to decide whether a source Object must be
        # materialized as a shared Object.  The one-object fixture is direct.
        visitor.object_uses = {"obj-1": 1}
        return visitor.convert_object(element)

    def test_sid_behaviors_preserve_authored_values(self):
        self.assertEqual(
            self.convert_object("sid_object", {
                "include_group": "false", "resolve_group": "true"}),
            {"capability": "windows.sid",
             "include_group": False, "resolve_group": True})
        self.assertEqual(
            self.convert_object("sid_sid_object", {
                "include_group": "true", "resolve_group": "false"}),
            {"capability": "windows.sid_sid",
             "include_group": True, "resolve_group": False})

    def test_sid_behavior_defaults_are_materialized(self):
        self.assertEqual(
            self.convert_object("sid_object"),
            {"capability": "windows.sid",
             "include_group": True, "resolve_group": False})
        self.assertEqual(
            self.convert_object("sid_sid_object"),
            {"capability": "windows.sid_sid",
             "include_group": True, "resolve_group": False})

    def test_sid_names_are_not_name_only_deprecation_holds(self):
        for local_name in ("sid_object", "sid_sid_object"):
            with self.subTest(local_name=local_name):
                element = ET.fromstring(
                    f'<w:{local_name} xmlns:w="{WINDOWS}" id="obj-1"/>')
                visitor = self.engine.AssessmentConverter(
                    None, None, self.mappings, human_compact=False,
                    native_recovery=True)
                mapping = visitor.capability(element, "object")
                self.assertIn(mapping["capability"],
                              ("windows.sid", "windows.sid_sid"))


if __name__ == "__main__":
    unittest.main()
