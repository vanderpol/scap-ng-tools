"""Native-only Input/Variable composition adapter: no hardcoded Input defaults."""
import unittest
from xml.etree import ElementTree as ET
from scap_ng_tools.converter.direct04 import load_runtime
from scap_ng_tools.converter.native041_function_lowering import lower_expression

class InputExpressionAdapter(unittest.TestCase):
    def test_input_and_decimal_cast_lower_recursively(self):
        expr = {"to_integer": {"function": {
            "name": "substring",
            "arguments": [{"input": "var-accounts-user-umask-input"}],
            "options": {"substring_start": 1, "substring_length": 1},
        }}}
        self.assertEqual(lower_expression(expr), {"to_integer": {"substring": {
            "substring_start": 1, "substring_length": 1,
            "value": {"input": "var-accounts-user-umask-input"}}}})
        for malformed in ({"to_integer": {"input": "a-input", "literal": "0"}},
                          {"input": "a-input", "literal": "0"}):
            with self.assertRaises(ValueError):
                lower_expression(malformed)

    def test_external_variable_composition_remains_dynamic(self):
        engine = load_runtime()
        variable = ET.Element("{%s}external_variable" % engine.OVAL,
                              {"id": "oval:test:var:4211", "datatype": "string"})
        class FakeSource:
            def node(self, component, ident, kind):
                return variable
        class FakeVisitor:
            native_recovery = True
            component_id = "component"
            source = FakeSource()
            def reference(self, ident, kind):
                return {"input": "var-accounts-user-umask-input"}
        node = ET.Element("{%s}variable_component" % engine.OVAL,
                          {"var_ref": "oval:test:var:4211"})
        self.assertEqual(engine.AssessmentConverter.function(FakeVisitor(), node),
                         {"input": "var-accounts-user-umask-input"})
        node.set("unexpected", "true")
        with self.assertRaises(Exception):
            engine.AssessmentConverter.function(FakeVisitor(), node)

    def test_installer_is_idempotent_and_pinned_source_unmodified(self):
        engine = load_runtime()
        original = engine.AssessmentConverter.function
        self.assertIs(load_runtime().AssessmentConverter.function, original)

if __name__ == "__main__":
    unittest.main()

class CollectedIntegerConversion(unittest.TestCase):
    def test_declared_int_collected_string_field_is_explicitly_converted(self):
        engine = load_runtime()
        mapping = {
            "capability": "independent.textfilecontent",
            "source": {
                "namespace": "http://oval.mitre.org/XMLSchema/oval-definitions-5#independent",
                "object": "textfilecontent54_object",
            },
            "native": {
                "state_field_map": {"subexpression": "subexpression"},
                "field_datatypes": {"subexpression": ["string", "integer"]},
                "test_source": {"kind": "host"},
            },
        }
        source_namespace = mapping["source"]["namespace"]
        source_object = mapping["source"]["object"]

        class Source:
            def node(self, _component, _identifier, _kind):
                return ET.fromstring(
                    f'<{source_object} xmlns="{source_namespace}"/>'
                )

        visitor = engine.AssessmentConverter(
            Source(), "component", [mapping], native_recovery=True
        )
        visitor.native_name = lambda _node, _kind: "collected-int-variable"
        visitor.reference = lambda _identifier, _kind: {
            "capability": "independent.textfilecontent",
            "full_path": {"equals": "/etc/group"},
        }
        element = ET.fromstring(
            '<local_variable xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" '
            'datatype="int"><object_component object_ref="obj" '
            'item_field="subexpression"/></local_variable>'
        )

        result = visitor.convert_variable(element)

        self.assertEqual(result, {"variable": "collected-int-variable"})
        self.assertEqual(
            visitor.variables["collected-int-variable"]["expression"].keys(),
            {"to_integer"},
        )
        self.assertEqual(
            visitor.conversion_warnings[-1]["code"],
            "oval_local_int_explicit_conversion",
        )

    def test_declared_int_integer_item_field_is_not_cast(self):
        engine = load_runtime()
        mapping = {
            "capability": "unix.file",
            "native": {"field_datatypes": {"owner_gid": ["integer"]}},
        }
        visitor = engine.AssessmentConverter(
            object(), "component", [mapping], native_recovery=True
        )
        visitor.native_name = lambda _node, _kind: "integer-item-variable"
        visitor.function = lambda _node: {
            "values": {
                "object": {"capability": "unix.file"},
                "field": "owner_gid",
            }
        }
        element = ET.fromstring(
            '<local_variable xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" '
            'datatype="int"><literal_component>ignored</literal_component></local_variable>'
        )

        visitor.convert_variable(element)

        self.assertEqual(
            visitor.variables["integer-item-variable"]["expression"],
            {"values": {"object": {"capability": "unix.file"}, "field": "owner_gid"}},
        )
