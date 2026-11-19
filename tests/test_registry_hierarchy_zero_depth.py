"""OVAL 5.12.3 Windows RegistryBehaviors recursion parity boundaries.

These are converter-unit semantics only. The original signed DotNet source
replay and RI Registry collector equivalence are separate release gates.
"""
import importlib
import unittest
from xml.etree import ElementTree as ET

from scap_ng_tools.converter.direct04 import load_runtime


REGISTRY = "{http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}behaviors"


class RegistryHierarchyBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The production loader installs the pinned visitor's helper modules.
        load_runtime()
        cls.helper = importlib.import_module("v04_direct_file_behaviors")

    def convert(self, attrs=None, *, key=None, native_recovery=True):
        behavior = ET.Element(REGISTRY, attrs or {}) if attrs is not None else None
        source_object = {
            "hive": {"equals": "local_machine"},
            "key": {"equals": "SOFTWARE\\Example"} if key is None else key,
            "name": {"matches_regex": ".*"},
        }
        result = self.helper.hierarchy_behaviors(
            behavior, source_object, native_recovery=native_recovery
        )
        return result, source_object

    def test_missing_behaviors_and_default_none_never_walk_recursively(self):
        for attrs in (None, {}, {"max_depth": "-1"},
                      {"recurse_direction": "none", "max_depth": "-1"},
                      {"recurse_direction": "none", "max_depth": "42"}):
            with self.subTest(attrs=attrs):
                result, source = self.convert(attrs)
                self.assertEqual(result, {})
                self.assertNotIn("traversal", source)

    def test_downward_zero_depth_does_not_emit_traversal(self):
        for lexical_depth in ("0", "00", "+0"):
            with self.subTest(depth=lexical_depth):
                result, _ = self.convert(
                    {"recurse_direction": "down", "max_depth": lexical_depth}
                )
                self.assertEqual(result, {})

    def test_downward_finite_and_unlimited_depth_are_preserved(self):
        fixtures = (
            ({"recurse_direction": "down", "max_depth": "1"}, 1),
            ({"recurse_direction": "down", "max_depth": "3"}, 3),
            ({"recurse_direction": "down", "max_depth": "-1"}, "unlimited"),
            ({"recurse_direction": "down"}, "unlimited"),
        )
        for attrs, expected_depth in fixtures:
            with self.subTest(attrs=attrs):
                result, _ = self.convert(attrs)
                self.assertEqual(result, {
                    "traversal": {"max_depth": expected_depth},
                })

    def test_deprecated_up_is_never_rewritten_as_down(self):
        for attrs in (
            {"recurse_direction": "up"},
            {"recurse_direction": "up", "max_depth": "0"},
            {"recurse_direction": "up", "max_depth": "-1"},
        ):
            with self.subTest(attrs=attrs):
                with self.assertRaisesRegex(
                    ValueError, "unsupported/deprecated hierarchy recursion direction"
                ):
                    self.convert(attrs)

    def test_downward_recursion_requires_equality_key(self):
        with self.assertRaisesRegex(ValueError, "equality key"):
            self.convert(
                {"recurse_direction": "down", "max_depth": "1"},
                key={"matches_regex": "SOFTWARE.*"},
            )

    def test_bad_depth_or_unknown_behavior_never_downgrades_to_none(self):
        for attrs, error in (
            ({"recurse_direction": "down", "max_depth": "-2"}, "max_depth"),
            ({"recurse_direction": "none", "max_depth": "unlimited"}, "max_depth"),
            ({"recurse_direction": "down", "other": "x"}, "attributes"),
        ):
            with self.subTest(attrs=attrs):
                with self.assertRaisesRegex(ValueError, error):
                    self.convert(attrs)


if __name__ == "__main__":
    unittest.main()
