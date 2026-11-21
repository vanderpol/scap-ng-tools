"""OVAL unique -> explicit lexical projection at collected evidence boundaries.

This is a syntactic/type admission candidate, not executable OVAL/RI/SCC
semantics or a license to reinterpret native authored unique operations.
"""
from copy import deepcopy
import unittest
from unittest.mock import patch

from scap_ng_tools.converter.native041_function_lowering import lower_expression


FIELD = {"values": {
    "object": {"capability": "independent.textfilecontent", "full_path": "/etc/audit/auditd.conf"},
    "field": "subexpression",
}}


class OVALUniqueLexicalProjection(unittest.TestCase):
    def source_unique(self, *operands):
        return {"function": {
            "name": "unique", "arguments": list(operands), "options": {},
        }}

    def test_source_collected_values_use_explicit_text_before_unique(self):
        source = self.source_unique(deepcopy(FIELD))
        before = deepcopy(source)
        expected = {"unique": {"concat": [
            {"literal": ""}, deepcopy(FIELD),
        ]}}
        self.assertEqual(lower_expression(source), expected)
        self.assertEqual(source, before)
        self.assertEqual(lower_expression(expected), expected)

    def test_multiple_ordered_components_preserve_multiplicity(self):
        left = deepcopy(FIELD)
        right = {"values": {
            "object": {"capability": "unix.password", "username": {"equals": "root"}},
            "field": "user_id",
        }}
        literal = {"literal": {"datatype": "string", "value": ["a", "a"]}}
        source = self.source_unique(left, literal, right)
        expected = {"unique": [
            {"concat": [{"literal": ""}, left]},
            {"concat": [{"literal": ""}, literal]},
            {"concat": [{"literal": ""}, right]},
        ]}
        self.assertEqual(lower_expression(source), expected)
        self.assertEqual(lower_expression(expected), expected)

    def test_native_unique_is_not_rewritten_without_source_envelope(self):
        native = {"unique": deepcopy(FIELD)}
        self.assertEqual(lower_expression(native), native)
        # A native author does not get an implicit string type for fields
        # whose schema permits multiple datatypes.

    def test_unknown_alias_and_typed_numeric_literal_are_projected(self):
        alias = {"variable": "source-variable"}
        integer = {"literal": {"datatype": "integer", "value": 1}}
        source = self.source_unique(alias, integer)
        expected = {"unique": [
            {"concat": [{"literal": ""}, alias]},
            {"concat": [{"literal": ""}, integer]},
        ]}
        self.assertEqual(lower_expression(source), expected)
        # The source adapter makes the lexical boundary explicit; it does not
        # evaluate the Variable or deduplicate the resulting population.

    def test_nested_source_split_string_conversion_remains_one_to_one(self):
        split = {"function": {
            "name": "split",
            "arguments": [deepcopy(FIELD)],
            "options": {"delimiter": ","},
        }}
        expression = lower_expression(self.source_unique(split))
        self.assertEqual(expression, {"unique": {"concat": [
            {"literal": ""}, {"split": {
                "delimiter": ",",
                "value": {"concat": [{"literal": ""}, deepcopy(FIELD)]},
            }},
        ]}})
        self.assertEqual(lower_expression(expression), expression)

    def test_bad_source_unique_arity_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unique source arity/options invalid"):
            lower_expression(self.source_unique())


class OVALUniqueLexicalTyping(unittest.TestCase):
    def test_mixed_numeric_and_string_source_values_share_lexical_domain(self):
        from scap_ng_tools.converter._v04_semantic.v04_variable_expressions import (
            assessment_variable_expressions,
        )
        source = {"function": {
            "name": "unique",
            "arguments": [
                {"literal": {"datatype": "integer", "value": 1}},
                {"literal": {"datatype": "string", "value": "1"}},
            ],
            "options": {},
        }}
        native = lower_expression(source)
        with patch(
            "scap_ng_tools.converter._v04_semantic.v04_variable_expressions.declaration_validator",
            return_value=type("NoSchemaErrors", (), {
                "iter_errors": staticmethod(lambda _declaration: iter(())),
            })(),
        ):
            self.assertEqual(
                assessment_variable_expressions({"variables": {
                    "result": {"kind": "local", "expression": native},
                }}),
                {"result": "string"},
            )
        # The lexical collision is intentionally left for runtime unique; the
        # converter preserves both source components and does not deduplicate.
        self.assertEqual(native["unique"][0]["concat"][1]["literal"]["value"], 1)
        self.assertEqual(native["unique"][1]["concat"][1]["literal"]["value"], "1")

    def test_record_source_operand_remains_a_fail_closed_hold(self):
        from scap_ng_tools.converter._v04_semantic.v04_variable_expressions import (
            assessment_variable_expressions,
        )
        native = lower_expression({"function": {
            "name": "unique",
            "arguments": [{"literal": {"datatype": "record", "value": {"id": 1}}}],
            "options": {},
        }})
        with patch(
            "scap_ng_tools.converter._v04_semantic.v04_variable_expressions.declaration_validator",
            return_value=type("NoSchemaErrors", (), {
                "iter_errors": staticmethod(lambda _declaration: iter(())),
            })(),
        ):
            with self.assertRaisesRegex(ValueError, "requires a scalar text operand"):
                assessment_variable_expressions({"variables": {
                    "result": {"kind": "local", "expression": native},
                }})


if __name__ == "__main__":
    unittest.main()
