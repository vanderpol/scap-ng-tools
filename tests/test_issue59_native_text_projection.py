"""Regression for Issue #59 native-expression text projection parity.

The source visitor can produce either a legacy function envelope or a native
expression. Both must use the same explicit, author-visible text boundary.
This tests syntax preservation, not OVAL/SCC/RI execution equivalence.
"""
from copy import deepcopy
import unittest

from scap_ng_tools.converter.native041_function_lowering import lower_expression


FIELD = {
    "values": {
        "object": {
            "capability": "independent.textfilecontent",
            "filepath": "/etc/audit/auditd.conf",
        },
        "field": "subexpression",
    }
}


class NativeTextProjection(unittest.TestCase):
    def test_native_split_and_substring_field_projection(self):
        cases = (
            ("split", {"delimiter": ","}),
            ("substring", {"substring_start": 1, "substring_length": -1}),
        )
        for operation, options in cases:
            with self.subTest(operation=operation):
                source = {operation: {**options, "value": deepcopy(FIELD)}}
                untouched = deepcopy(source)
                converted = lower_expression(source)
                self.assertEqual(source, untouched)
                self.assertEqual(converted, {operation: {
                    **options,
                    "value": {"concat": [{"literal": ""}, deepcopy(FIELD)]},
                }})
                # Lowering must be deterministic and idempotent.
                self.assertEqual(lower_expression(converted), converted)

    def test_source_envelope_and_native_expression_match(self):
        for name, options in (
            ("split", {"delimiter": ","}),
            ("substring", {"substring_start": 2, "substring_length": 4}),
        ):
            with self.subTest(name=name):
                legacy = {"function": {
                    "name": name, "arguments": [deepcopy(FIELD)],
                    "options": options,
                }}
                native = {name: {**options, "value": deepcopy(FIELD)}}
                self.assertEqual(lower_expression(legacy), lower_expression(native))

    def test_no_unapproved_literal_or_variable_cast(self):
        # An integer literal is deliberately *not* rewritten to string.
        # The semantic checker may reject it in a text consumer.
        for operand in (
            {"literal": {"datatype": "integer", "value": 17}},
            {"variable": "unknown-variable"},
            {"concat": [{"literal": ""}, deepcopy(FIELD)]},
        ):
            with self.subTest(operand=operand):
                source = {"split": {"delimiter": ",", "value": operand}}
                self.assertEqual(lower_expression(source), source)

    def test_population_and_error_boundaries_not_executed(self):
        # The adapter encodes one-to-one lexical projection; it does not
        # invent collected Items or convert unknown/error into empty strings.
        expression = lower_expression({"split": {
            "delimiter": ",", "value": deepcopy(FIELD),
        }})
        operands = expression["split"]["value"]["concat"]
        self.assertEqual(operands[0], {"literal": ""})
        self.assertEqual(operands[1], FIELD)
        self.assertNotIn("datatype", expression["split"]["value"])
        self.assertNotIn("value", operands[1]["values"])


if __name__ == "__main__":
    unittest.main()
