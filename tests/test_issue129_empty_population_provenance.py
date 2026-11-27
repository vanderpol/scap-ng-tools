"""Issue #129: converter preserves empty-population provenance and grammar."""
from pathlib import Path
import unittest
from unittest.mock import patch

from scap_ng_tools.converter import native041_function_lowering
from scap_ng_tools.converter._v04_semantic import v04_variable_expressions as semantic


class _CandidateSchema:
    def iter_errors(self, declaration):
        return iter(())


class EmptyPopulationProvenance(unittest.TestCase):
    def infer(self, variables):
        with patch.object(semantic, "declaration_validator", return_value=_CandidateSchema()):
            return semantic.assessment_variable_expressions({"variables": variables})

    def test_typed_empty_alias_and_functions_keep_derived_types(self):
        variables = {
            "empty-variable": {"kind": "constant", "expression": {"literal": {
                "datatype": "string", "value": []}}},
            "alias-variable": {"kind": "local", "expression": {
                "variable": "empty-variable"}},
            "unique-variable": {"kind": "local", "expression": {
                "unique": {"variable": "empty-variable"}}},
            "concat-variable": {"kind": "local", "expression": {
                "concat": [{"literal": "prefix"}, {"variable": "empty-variable"}]}},
            "count-variable": {"kind": "local", "expression": {
                "count": {"variable": "empty-variable"}}},
        }
        self.assertEqual(self.infer(variables), {
            "empty-variable": "string", "alias-variable": "string",
            "unique-variable": "string", "concat-variable": "string",
            "count-variable": "integer",
        })

    def test_untyped_empty_remains_an_explicit_authoring_hold(self):
        with self.assertRaisesRegex(ValueError, "ambiguous/empty"):
            self.infer({"empty-variable": {"kind": "constant", "expression": {
                "literal": []}}})

    def test_collected_empty_projection_is_not_rewritten_or_fabricated(self):
        expression = {"values": {"object": "source-object", "field": "subexpression"}}
        self.assertEqual(native041_function_lowering.lower_expression(expression), expression)
        self.assertNotIn("literal", str(native041_function_lowering.lower_expression(expression)))


if __name__ == "__main__":
    unittest.main()
