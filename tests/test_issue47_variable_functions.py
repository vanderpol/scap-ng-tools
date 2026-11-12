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

    def test_inactive_functions_and_variadic_aggregations_fail_closed(self):
        import xml.etree.ElementTree as ET
        self._visitor()  # load the runtime module aliases
        from v04_direct_scap_source import OVAL
        for operation, attrs, children in (
            ("split", " delimiter=','", "<literal_component datatype='string'>a,b</literal_component>"),
            ("arithmetic", " arithmetic_operation='add'", "<literal_component datatype='integer'>1</literal_component><literal_component datatype='integer'>2</literal_component>"),
            ("unique", "", "<literal_component datatype='string'>a</literal_component><literal_component datatype='string'>b</literal_component>"),
        ):
            with self.subTest(operation=operation):
                source = ET.fromstring(f"<{operation} xmlns='{OVAL}'{attrs}>{children}</{operation}>")
                with self.assertRaises(ValueError):
                    self._visitor().function(source)


if __name__ == "__main__":
    unittest.main()
