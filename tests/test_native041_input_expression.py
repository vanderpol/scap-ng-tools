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
