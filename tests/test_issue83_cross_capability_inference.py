"""Generic OVAL Test capability inference and fail-closed boundaries."""
import unittest
import xml.etree.ElementTree as ET

from scap_ng_tools.converter.direct04 import load_runtime

load_runtime()
from v04_direct_converter import AssessmentConverter  # noqa: E402
from v04_direct_scap_source import OVAL, UnsupportedSource  # noqa: E402


WINDOWS = OVAL + "#windows"
INDEPENDENT = OVAL + "#independent"


def node(xml):
    return ET.fromstring(xml)


class Source:
    def __init__(self, nodes):
        self.nodes = {"component": {item.get("id"): item for item in nodes}}

    def node(self, _component, identifier, _kind):
        return self.nodes["component"][identifier]

    def object_uses(self, _component, _identifier, _kind):
        return {}


def mapping(capability, namespace, test, object_name, state_name):
    return {
        "capability": capability,
        "source": {"namespace": namespace, "test": test,
                   "object": object_name, "state": state_name},
        "native": {"test_source": {"kind": "object"},
                   "selector_map": {}, "state_field_map": {"value": "value"}},
    }


class CrossCapabilityInferenceTests(unittest.TestCase):
    def mappings(self):
        return [
            mapping("windows.appcmd", WINDOWS, "appcmd_test", "appcmd_object", "appcmd_state"),
            mapping("independent.shellcommand", INDEPENDENT, "shellcommand_test",
                    "shellcommand_object", "shellcommand_state"),
            mapping("independent.variable.value", INDEPENDENT, "variable_test",
                    "variable_object", "variable_state"),
            mapping("independent.other", INDEPENDENT, "other_test", "other_object", "other_state"),
        ]

    def test_matching_object_state_overrides_wrong_test_wrapper_and_preserves_namespace(self):
        test = node(
            f'<appcmd_test xmlns="{WINDOWS}" id="tst-1" check="all">'
            '<object object_ref="obj-1"/><state state_ref="st-1"/></appcmd_test>')
        source = Source([
            node(f'<shellcommand_object xmlns="{INDEPENDENT}" id="obj-1"/>'),
            node(f'<shellcommand_state xmlns="{INDEPENDENT}" id="st-1"/>'),
        ])
        visitor = AssessmentConverter(source, "component", self.mappings(), human_compact=False)
        visitor.reference = lambda identifier, kind: (
            {"capability": "independent.shellcommand"} if kind == "object" else
            {"fields": {"value": {"values_found": "one_or_more", "values_matching": "every", "equals": "ok"}}})
        visitor.same_family = lambda *_args: None
        result = visitor.convert_test(test)
        self.assertEqual(visitor.tests[result["test"]]["capability"], "independent.shellcommand")
        warning = visitor.conversion_warnings[0]
        self.assertEqual(warning["code"], "oval_test_capability_inferred_from_object_state")
        self.assertEqual(warning["source_test_capability"], "windows.appcmd")
        self.assertEqual(warning["inferred_capability"], "independent.shellcommand")

    def test_mismatched_object_and_state_does_not_override_existing_test_mapping(self):
        test = node(
            f'<appcmd_test xmlns="{WINDOWS}" id="tst-2" check="all">'
            '<object object_ref="obj-2"/><state state_ref="st-2"/></appcmd_test>')
        source = Source([
            node(f'<shellcommand_object xmlns="{INDEPENDENT}" id="obj-2"/>'),
            node(f'<other_state xmlns="{INDEPENDENT}" id="st-2"/>'),
        ])
        visitor = AssessmentConverter(source, "component", self.mappings(), human_compact=False)
        resolved = visitor.resolve_test_capability(test)
        self.assertEqual(resolved["capability"], "windows.appcmd")
        self.assertEqual(visitor.conversion_warnings, [])

    def test_mismatched_object_and_state_without_test_mapping_fails_closed(self):
        test = node(
            f'<unknown_test xmlns="{WINDOWS}" id="tst-3" check="all">'
            '<object object_ref="obj-3"/><state state_ref="st-3"/></unknown_test>')
        source = Source([
            node(f'<shellcommand_object xmlns="{INDEPENDENT}" id="obj-3"/>'),
            node(f'<other_state xmlns="{INDEPENDENT}" id="st-3"/>'),
        ])
        visitor = AssessmentConverter(source, "component", self.mappings(), human_compact=False)
        with self.assertRaises(UnsupportedSource):
            visitor.resolve_test_capability(test)

    def test_filter_capability_is_not_authorized_by_direct_pair_inference(self):
        # A matching direct pair may still contain a Set/Filter whose State is
        # from another capability. The fallback does not inspect or erase that
        # nested relation; the ordinary Object conversion must reject it.
        test = node(
            f'<variable_test xmlns="{INDEPENDENT}" id="tst-4" check="all">'
            '<object object_ref="obj-4"/><state state_ref="st-4"/></variable_test>')
        obj = node(
            f'<variable_object xmlns="{INDEPENDENT}" id="obj-4">'
            '<set set_operator="UNION"><object_reference>leaf-4</object_reference>'
            '<filter action="include">bad-4</filter></set></variable_object>')
        source = Source([
            obj,
            node(f'<variable_state xmlns="{INDEPENDENT}" id="st-4"/>'),
            node(f'<appcmdlistconfig_state xmlns="{WINDOWS}" id="bad-4"/>'),
            node(f'<variable_object xmlns="{INDEPENDENT}" id="leaf-4"><var_ref>v-4</var_ref></variable_object>'),
            node(f'<constant_variable xmlns="{OVAL}" id="v-4" datatype="string"><value>x</value></constant_variable>'),
        ])
        visitor = AssessmentConverter(source, "component", self.mappings(), human_compact=False)
        # The direct Test pair is validly variable.value; the nested filter
        # remains a separate source-invalid relation and must not be inferred.
        self.assertEqual(visitor.resolve_test_capability(test)["capability"],
                         "independent.variable.value")
        with self.assertRaises(UnsupportedSource):
            visitor.convert_object(obj)


if __name__ == "__main__":
    unittest.main()
