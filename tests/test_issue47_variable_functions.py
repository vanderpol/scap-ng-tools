"""Focused qualification for the active 0.4 Variable-function contract.

These tests check source-shape preservation and the independent OVAL reference
vectors. They do not assert scanner/runtime equivalence.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
from issue28_semantics import Outcome, count, flatten_components, unique


class Issue47Reports(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = ROOT / "docs/evidence/issue47/function-regression"
        cls.regression = json.loads((root / "RULE-REGRESSION-REPORT.json").read_text())
        cls.matrix = json.loads((root / "FUNCTION-SUPPORT-MATRIX.json").read_text())

    def test_exact_rule_regression_reconciliation(self):
        summary = self.regression["regression_summary"]
        self.assertEqual(summary["count"], 55)
        self.assertEqual(summary["status_delta"], {"converted->blocked": 55})
        self.assertEqual(summary["classifications"], {
            "inactive_function_envelope": 50,
            "unrelated_datatype_or_schema_blocker": 5,
        })
        self.assertEqual(summary["count_bearing_regressions"], 0)
        self.assertEqual(len({(r["benchmark"], r["source_rule"])
                              for r in self.regression["regressions"]}), 55)

    def test_matrix_pins_active_grammar_and_inventory(self):
        self.assertEqual(self.matrix["schema_contract"]["active_functions"],
                         ["concat", "regex_capture", "unique", "count", "merge"])
        rows = {row["function"]: row for row in self.matrix["rows"]}
        self.assertEqual(rows["count"]["source_occurrences"], 47)
        self.assertEqual(rows["count"]["source_rules"], 37)
        self.assertEqual(rows["count"]["source_variables"], 29)
        self.assertEqual(rows["split"]["active_0_4"], False)
        self.assertEqual(rows["split"]["source_occurrences"], 29)


class ActiveCountVectors(unittest.TestCase):
    def test_empty_duplicates_nested_and_incomplete_population(self):
        self.assertEqual(count([]), 0)
        self.assertEqual(count(flatten_components([["a", "a"], ["b"]])), 3)
        self.assertEqual(count([count(["x", "y"])]), 1)
        self.assertEqual(count([Outcome.INCOMPLETE]), Outcome.INCOMPLETE)

    def test_all_diagnostic_states_are_propagated(self):
        for state in (Outcome.ERROR, Outcome.UNKNOWN, Outcome.NOT_EVALUATED,
                      Outcome.NOT_APPLICABLE, Outcome.INCOMPLETE,
                      Outcome.NOT_COLLECTED):
            with self.subTest(state=state):
                self.assertEqual(count([state]), state)

    def test_unique_keeps_first_occurrence_and_empty_is_valid(self):
        self.assertEqual(unique(["b", "a", "b", ""]), ["b", "a", ""])
        self.assertEqual(unique([]), [])

    def test_missing_variable_is_not_an_empty_success(self):
        from scap_ng_tools.converter._v04_semantic.v04_variable_expressions import (
            assessment_variable_expressions)
        class NoSchemaErrors:
            @staticmethod
            def iter_errors(_):
                return iter(())
        with patch("scap_ng_tools.converter._v04_semantic.v04_variable_expressions.declaration_validator",
                   return_value=NoSchemaErrors()), self.assertRaisesRegex(ValueError, "unresolved Variable"):
            assessment_variable_expressions({"variables": {
                "result-variable": {"kind": "local", "datatype": "integer",
                                     "expression": {"variable": "missing-variable"}}
            }})

    def test_restored_forms_have_semantic_datatypes_and_nested_arrays(self):
        from scap_ng_tools.converter._v04_semantic.v04_variable_expressions import (
            assessment_variable_expressions)
        class NoSchemaErrors:
            @staticmethod
            def iter_errors(_):
                return iter(())
        declarations = {
            'split-variable': {'kind': 'local', 'datatype': 'string', 'expression':
                {'split': {'delimiter': ',', 'value': {'literal': 'a,b'}}}},
            'substring-variable': {'kind': 'local', 'datatype': 'string', 'expression':
                {'substring': {'substring_start': 1, 'substring_length': 1, 'value': {'literal': 'ab'}}}},
            'arithmetic-variable': {'kind': 'local', 'datatype': 'integer', 'expression':
                {'arithmetic': {'arithmetic_operation': 'add', 'values': [
                    {'literal': 1}, {'literal': [2, 3]}]}}},
            'unique-variable': {'kind': 'local', 'datatype': 'string', 'expression':
                {'unique': [{'literal': ['a', 'a']}, {'literal': ['b']}] }},
            'merge-variable': {'kind': 'local', 'datatype': 'string', 'expression':
                {'merge': {'delimiter': ',', 'sort': 'document', 'order': 'ascending',
                           'values': [{'literal': ['a']}, {'literal': ['b']}]}}},
        }
        with patch('scap_ng_tools.converter._v04_semantic.v04_variable_expressions.declaration_validator',
                   return_value=NoSchemaErrors()):
            result = assessment_variable_expressions({'variables': declarations})
        self.assertEqual(result['arithmetic-variable'], 'integer')
        self.assertEqual(result['merge-variable'], 'string')

    def test_count_result_is_integer_typed(self):
        from scap_ng_tools.converter._v04_semantic.v04_variable_expressions import (
            assessment_variable_expressions)
        class NoSchemaErrors:
            @staticmethod
            def iter_errors(_):
                return iter(())
        with patch("scap_ng_tools.converter._v04_semantic.v04_variable_expressions.declaration_validator",
                   return_value=NoSchemaErrors()):
            self.assertEqual(assessment_variable_expressions({"variables": {
                "result-variable": {"kind": "local", "datatype": "integer",
                                     "expression": {"count": {"literal": []}}}
            }}), {"result-variable": "integer"})


class ActiveConverterAdmission(unittest.TestCase):
    @staticmethod
    def _visitor():
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_converter import AssessmentConverter
        return AssessmentConverter(None, None, [], native_recovery=True)

    def test_count_is_recursive_native_syntax(self):
        import xml.etree.ElementTree as ET
        visitor = self._visitor()
        from v04_direct_scap_source import OVAL
        source = ET.fromstring(f"<count xmlns='{OVAL}'><count><literal_component datatype='string'>x</literal_component></count></count>")
        self.assertEqual(visitor.function(source), {"count": {"count": {
            "literal": {"datatype": "string", "value": "x"}}}})

    def test_restored_functions_and_variadic_aggregations_use_native_forms(self):
        import xml.etree.ElementTree as ET
        self._visitor()  # load the runtime module aliases
        from v04_direct_scap_source import OVAL
        cases = (
            ('split', " delimiter=','", "<literal_component datatype='string'>a,b</literal_component>",
             {'split': {'delimiter': ',', 'value': {'literal': {'datatype': 'string', 'value': 'a,b'}}}}),
            ('arithmetic', " arithmetic_operation='add'", "<literal_component datatype='int'>1</literal_component><literal_component datatype='int'>2</literal_component>",
             {'arithmetic': {'arithmetic_operation': 'add', 'values': [
                 {'literal': {'datatype': 'integer', 'value': 1}},
                 {'literal': {'datatype': 'integer', 'value': 2}}]}}),
            ('unique', '', "<literal_component datatype='string'>a</literal_component><literal_component datatype='string'>b</literal_component>",
             {'unique': [{'literal': {'datatype': 'string', 'value': 'a'}},
                         {'literal': {'datatype': 'string', 'value': 'b'}}]}),
        )
        for operation, attrs, children, expected in cases:
            with self.subTest(operation=operation):
                source = ET.fromstring(f"<{operation} xmlns='{OVAL}'{attrs}>{children}</{operation}>")
                self.assertEqual(self._visitor().function(source), expected)

    def test_inactive_generic_function_envelope_remains_rejected(self):
        from pathlib import Path
        import sys
        sys.path.insert(0, str(Path(__file__).parents[1] / 'src/scap_ng_tools/converter/_v04_runtime'))
        from v04_variable_function_migration import canonical_expression, UnsupportedExpression
        with self.assertRaisesRegex(UnsupportedExpression, 'inactive function envelope'):
            canonical_expression({'function': {'name': 'split', 'arguments': [], 'options': {}}})



if __name__ == "__main__":
    unittest.main()
