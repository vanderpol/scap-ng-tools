"""Issue #59: transactional lowering and fail-closed type-boundary regressions.

These tests exercise only the source-envelope -> native 0.4.1 AST adapter.
They intentionally do NOT claim OVAL, RI, or SCC runtime equivalence.
"""
from copy import deepcopy
import unittest

from scap_ng_tools.converter.native041_function_lowering import (
    lower_assessment_inplace,
    lower_expression,
)


def source_unique(*args):
    return {"function": {
        "name": "unique", "arguments": list(args), "options": {},
    }}


def collected(field="subexpression"):
    return {"values": {
        "object": {
            "capability": "independent.textfilecontent",
            "filepath": "/etc/audit/auditd.conf",
        },
        "field": field,
    }}


class AtomicLoweringBoundaries(unittest.TestCase):
    def test_successful_assessment_lowering_only_changes_expressions(self):
        field = collected()
        document = {"assessment": {
            "id": "source-identity-preserved",
            "variables": {
                "first": {"kind": "local", "expression": source_unique(field)},
                "second": {"kind": "local", "expression": {"literal": "stable"}},
            },
            "tests": {"original": {"source": "retain-provenance"}},
        }}
        before = deepcopy(document)
        self.assertTrue(lower_assessment_inplace(document))
        self.assertEqual(
            document["assessment"]["variables"]["first"]["expression"],
            {"unique": {"concat": [{"literal": ""}, field]}},
        )
        self.assertEqual(
            document["assessment"]["variables"]["second"],
            before["assessment"]["variables"]["second"],
        )
        self.assertEqual(
            document["assessment"]["tests"], before["assessment"]["tests"]
        )
        self.assertEqual(document["assessment"]["id"], "source-identity-preserved")
        self.assertFalse(lower_assessment_inplace(document))

    def test_invalid_late_variable_does_not_partially_modify_assessment(self):
        document = {"assessment": {"variables": {
            "early": {"expression": source_unique(collected())},
            "late": {"expression": {"function": {
                "name": "unsupported_operation",
                "arguments": [{"literal": "x"}],
                "options": {},
            }}},
        }}}
        original = deepcopy(document)
        with self.assertRaisesRegex(ValueError, "unsupported native function envelope"):
            lower_assessment_inplace(document)
        self.assertEqual(document, original)

    def test_invalid_nested_source_expression_does_not_partially_modify(self):
        document = {"assessment": {"variables": {
            "outer": {"expression": source_unique(
                collected(),
                {"function": {
                    "name": "count",
                    "arguments": [{"literal": 1}, {"literal": 2}],
                    "options": {},
                }},
            )},
        }}}
        before = deepcopy(document)
        with self.assertRaisesRegex(ValueError, "multi-component OVAL count"):
            lower_assessment_inplace(document)
        self.assertEqual(document, before)

    def test_native_unique_preserves_collected_type_boundary(self):
        field = collected()
        source = {"unique": deepcopy(field)}
        self.assertEqual(lower_expression(source), source)
        self.assertEqual(lower_expression(lower_expression(source)), source)

    def test_source_unique_never_silently_converts_typed_literals_or_aliases(self):
        for operand in (
            {"literal": {"datatype": "integer", "value": 1}},
            {"literal": {"datatype": "string", "value": "001"}},
            {"variable": "external-source-variable"},
        ):
            with self.subTest(operand=operand):
                native = lower_expression(source_unique(deepcopy(operand)))
                self.assertEqual(native, {"unique": operand})
                self.assertEqual(lower_expression(native), native)

    def test_source_unique_keeps_collection_expression_unevaluated(self):
        field = collected()
        lowered = lower_expression(source_unique(field))
        self.assertEqual(
            lowered,
            {"unique": {"concat": [{"literal": ""}, field]}},
        )
        # Only a reference is authored. Missing/empty/error statuses cannot
        # be synthesized or treated as observed lexical values here.
        self.assertNotIn("status", lowered)
        self.assertNotIn("datatype", lowered)
        self.assertEqual(lower_expression(lowered), lowered)


if __name__ == "__main__":
    unittest.main()
