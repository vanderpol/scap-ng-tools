"""OVAL unique -> explicit lexical projection at collected evidence boundaries.

This is a syntactic/type admission candidate, not executable OVAL/RI/SCC
semantics or a license to reinterpret native authored unique operations.
"""
from copy import deepcopy
import unittest

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
            literal,
            {"concat": [{"literal": ""}, right]},
        ]}
        self.assertEqual(lower_expression(source), expected)
        self.assertEqual(lower_expression(expected), expected)

    def test_native_unique_is_not_rewritten_without_source_envelope(self):
        native = {"unique": deepcopy(FIELD)}
        self.assertEqual(lower_expression(native), native)
        # A native author does not get an implicit string type for fields
        # whose schema permits multiple datatypes.

    def test_unknown_alias_and_typed_numeric_literal_remain_unmodified(self):
        alias = {"variable": "source-variable"}
        integer = {"literal": {"datatype": "integer", "value": 1}}
        source = self.source_unique(alias, integer)
        expected = {"unique": [alias, integer]}
        self.assertEqual(lower_expression(source), expected)
        # Native semantic typing must still reject incompatible domains;
        # no lossy stringification of known literal datatypes is inferred.

    def test_nested_source_split_string_conversion_remains_one_to_one(self):
        split = {"function": {
            "name": "split",
            "arguments": [deepcopy(FIELD)],
            "options": {"delimiter": ","},
        }}
        expression = lower_expression(self.source_unique(split))
        self.assertEqual(expression, {"unique": {"split": {
            "delimiter": ",",
            "value": {"concat": [{"literal": ""}, deepcopy(FIELD)]},
        }}})
        self.assertEqual(lower_expression(expression), expression)

    def test_bad_source_unique_arity_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unique source arity/options invalid"):
            lower_expression(self.source_unique())


if __name__ == "__main__":
    unittest.main()
