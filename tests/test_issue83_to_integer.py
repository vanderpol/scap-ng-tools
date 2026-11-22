"""Canonical 0.4.1 to_integer datatype and lexical admission vectors."""
import copy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import unittest

from scap_ng_tools.converter._v04_semantic import v04_variable_expressions as semantic

RULE_ID = "xccdf_mil.disa.stig_rule_SV-221718r991590_rule"


class _NoSchemaErrors:
    @staticmethod
    def iter_errors(_declaration):
        return iter(())


class ToIntegerSemanticVectors(unittest.TestCase):
    @staticmethod
    def _validate(expression, *, inputs=None):
        assessment = {
            "variables": {"candidate": {"kind": "local", "expression": expression}},
        }
        if inputs is not None:
            assessment["inputs"] = inputs
        with patch.object(semantic, "declaration_validator", return_value=_NoSchemaErrors()), \
             patch.object(semantic, "snapshot", return_value=SimpleNamespace(schema_root=Path("."))):
            return semantic.assessment_variable_expressions(assessment)

    def test_signed_decimal_and_leading_zero_literals_are_integer(self):
        for value in ("077", "+007", "-0", "12"):
            with self.subTest(value=value):
                self.assertEqual(
                    self._validate({"to_integer": {"literal": {
                        "datatype": "string", "value": value}}}),
                    {"candidate": "integer"})

    def test_multivalue_literals_preserve_elementwise_integer_domain(self):
        self.assertEqual(
            self._validate({"to_integer": {"literal": {
                "datatype": "string", "value": ["077", "027", "022", "007"]}}}),
            {"candidate": "integer"})

    def test_required_input_is_typed_from_string_to_integer(self):
        self.assertEqual(
            self._validate({"to_integer": {"input": "umask"}}, inputs={
                "umask": {"datatype": "string", "required": True,
                          "cardinality": "exactly_one"}}),
            {"candidate": "integer"})

    def test_empty_string_population_is_allowed_but_invalid_token_fails_closed(self):
        self.assertEqual(
            self._validate({"to_integer": {"literal": {
                "datatype": "string", "value": []}}}),
            {"candidate": "integer"})
        for value in ("", "077x", "0x4f", "7.0", " "):
            with self.subTest(value=value), self.assertRaisesRegex(
                    ValueError, "signed decimal digits"):
                self._validate({"to_integer": {"literal": {
                    "datatype": "string", "value": value}}})

    def test_behavioral_mutation_that_accepts_bad_decimal_is_caught(self):
        # Keep the dispatch branch present but mutate its lexical predicate to
        # accept everything. The production semantic admission witness must
        # still reject the source-invalid decimal token.
        def expected_invalid():
            with self.assertRaisesRegex(ValueError, "signed decimal digits"):
                self._validate({"to_integer": {"literal": {
                    "datatype": "string", "value": "077x"}}})

        with patch.object(semantic.re, "fullmatch", return_value=object()):
            self.assertRaises(AssertionError, expected_invalid)

    def test_non_string_record_numeric_and_malformed_operands_fail_closed(self):
        cases = (
            {"to_integer": {"literal": {"datatype": "integer", "value": 7}}},
            {"to_integer": {"literal": {"datatype": "record", "value": {}}}},
            {"to_integer": {"literal": {"datatype": "string", "value": "7"},
                             "literal2": "8"}},
            {"to_integer": "077"},
        )
        for expression in cases:
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                self._validate(expression)


class ToIntegerSourceReplay(unittest.TestCase):
    """Run the signed Oracle Linux source when fixtures are explicitly supplied."""

    @classmethod
    def setUpClass(cls):
        source = os.environ.get("SCAP_NG_TO_INTEGER_SOURCE")
        schema = os.environ.get("SCAP_NG_SCHEMA_ROOT")
        if not source or not schema:
            raise unittest.SkipTest(
                "Set SCAP_NG_TO_INTEGER_SOURCE and SCAP_NG_SCHEMA_ROOT for source replay")
        cls.source = Path(source)
        cls.schema = Path(schema)
        cls.source_sha256 = hashlib.sha256(cls.source.read_bytes()).hexdigest()

    def test_pinned_rule_focused_and_benchmark_admission(self):
        from scap_ng_tools.converter.direct04 import convert_benchmark, convert_focused
        documents, trace = convert_focused(
            schema_root=self.schema, source=self.source,
            sha256_pin=self.source_sha256, rule_ids=[RULE_ID],
            native_recovery=True)
        self.assertTrue(documents)
        self.assertEqual(trace["source_zip_sha256"], self.source_sha256)
        assessment = next(doc["assessment"] for doc in documents.values()
                          if "assessment" in doc and doc["assessment"].get("mode") == "automated")
        self.assertTrue(any("to_integer" in json.dumps(value)
                            for value in assessment["variables"].values()))

        _, _, coverage = convert_benchmark(
            schema_root=self.schema, source=self.source,
            sha256_pin=self.source_sha256, native_recovery=True)
        row = next(item for item in coverage["rules"] if item["source_rule"] == RULE_ID)
        self.assertEqual(row["status"], "converted")
        self.assertEqual(row["proof_level"], "authoring_validated")

    def test_production_semantic_gate_rejects_invalid_to_integer_literal(self):
        from scap_ng_tools.converter._v04_semantic.validation import document_errors
        from scap_ng_tools.converter.direct04 import convert_focused, load_pinned_snapshot
        documents, _ = convert_focused(
            schema_root=self.schema, source=self.source,
            sha256_pin=self.source_sha256, rule_ids=[RULE_ID],
            native_recovery=True)
        assessment_doc = next(doc for doc in documents.values()
                              if "assessment" in doc and doc["assessment"].get("mode") == "automated")
        invalid = copy.deepcopy(assessment_doc)
        variables = invalid["assessment"]["variables"]
        target = next(name for name, value in variables.items()
                      if "to_integer" in value.get("expression", {}))
        variables[target]["expression"]["to_integer"] = {
            "literal": {"datatype": "string", "value": "077x"}}
        errors = list(document_errors(load_pinned_snapshot(self.schema), "assessment", invalid))
        self.assertTrue(errors)
        self.assertTrue(any("signed decimal digits" in error.message
                            or "to_integer" in error.message for error in errors))


if __name__ == "__main__":
    unittest.main()
