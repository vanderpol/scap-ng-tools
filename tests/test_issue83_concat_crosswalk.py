"""Generic OVAL 5.12.3 textual-function crosswalk vectors.

These tests exercise the converter's typed admission gate, not scanner or OVAL
runtime equivalence.  Collection expansion and status propagation remain
runtime obligations; the source oracle is covered separately in tools/.
"""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import unittest

from scap_ng_tools.converter._v04_semantic import v04_variable_expressions as semantic


class _NoSchemaErrors:
    @staticmethod
    def iter_errors(_declaration):
        return iter(())


class OVALConcatCrosswalk(unittest.TestCase):
    @staticmethod
    def _assessment(expression, field_types=None):
        field_types = field_types or ["string", "integer"]
        capability = "windows.registry"
        generated = {
            "fields": {"value": field_types},
            "records": [], "selectors": {}, "native": {},
        }
        mapping = {"native": {"field_datatypes": {"value": field_types}}}
        return {"variables": {"captured-variable": {
            "kind": "local", "expression": expression,
        }}}, generated, mapping, capability

    def _validate(self, expression, *, field_types=None):
        assessment, generated, mapping, capability = self._assessment(
            expression, field_types)
        values = expression
        with patch.object(semantic, "declaration_validator", return_value=_NoSchemaErrors()), \
             patch.object(semantic, "snapshot", return_value=SimpleNamespace(schema_root=Path("."))), \
             patch("scap_ng_tools.converter._v04_semantic.v04_object_contract.object_validator",
                   return_value=SimpleNamespace(iter_errors=lambda _: iter(()))), \
             patch.object(semantic, "contract", return_value=(
                 generated["fields"], set(), {}, generated["native"])), \
             patch.object(semantic, "capability_contract", return_value=(mapping, generated)):
            return semantic.assessment_variable_expressions(assessment)

    def test_concat_accepts_mixed_typed_collected_population(self):
        values = {"values": {"object": {"capability": "windows.registry"},
                              "field": "value"}}
        expression = {"concat": [values, {"literal": {"datatype": "string",
                                                          "value": ".config"}}]}
        self.assertEqual(self._validate(expression),
                         {"captured-variable": "string"})

    def test_all_textual_consumers_share_collection_cast_boundary(self):
        values = {"values": {"object": {"capability": "windows.registry"},
                              "field": "value"}}
        cases = {
            "split": {"delimiter": ",", "value": values},
            "substring": {"substring_start": 1, "substring_length": 3,
                           "value": values},
            "begin": {"character": "C:", "value": values},
            "end": {"character": "\\", "value": values},
            "regex_capture": {"pattern": r"(.*)", "value": values},
        }
        for operation, payload in cases.items():
            with self.subTest(operation=operation):
                self.assertEqual(self._validate({operation: payload}),
                                 {"captured-variable": "string"})

    def test_record_population_is_not_silently_stringified(self):
        expression = {"concat": [
            {"literal": {"datatype": "record", "value": {"id": 1}}},
            {"literal": "suffix"},
        ]}
        with self.assertRaisesRegex(ValueError, "requires a scalar text operand"):
            self._validate(expression, field_types=["string"])

    def test_empty_collection_remains_a_fail_closed_authoring_hold(self):
        expression = {"concat": [
            {"literal": []},
            {"literal": "suffix"},
        ]}
        with self.assertRaisesRegex(ValueError, "requires a scalar text operand"):
            self._validate(expression, field_types=["string"])


if __name__ == "__main__":
    unittest.main()
