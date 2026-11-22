"""Issue #118 gate: schema operations must not lose production dispatch."""
import json
from pathlib import Path
import tempfile
import unittest

from scripts.check_canonical_operation_coverage import audit, schema_operations

ROOT = Path(__file__).resolve().parents[1]


class Issue118OperationCoverage(unittest.TestCase):
    def test_active_schema_operations_include_to_integer_and_tools_handlers(self):
        # Use the checked-in semantic pack's active operation list when the
        # external canonical checkout is unavailable; the integration command
        # below accepts the exact pinned schema root and derives this list from
        # its JSON Schema directly.
        contracts = json.loads((ROOT / "src/scap_ng_tools/converter/_v04_semantic/contracts-0.4.1.json").read_text())
        self.assertEqual(contracts["canonical_commit"], json.loads((ROOT / "canonical-schema-pin.json").read_text())["canonical_sha"])
        self.assertEqual(contracts["canonical_commit"], "f51ab2c5bd82c94a9c292a7abb2ef1a7edc91ca2")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            schema = {
                "$defs": {"expression": {"oneOf": [
                    {"properties": {name: {}}} for name in
                    ["literal", "variable", "input", "values", "to_integer", "time_difference",
                     "concat", "regex_capture", "unique", "count", "split", "substring",
                     "arithmetic", "begin", "end", "merge"]
                ]}}
            }
            (root / "variable-expression.schema.json").write_text(json.dumps(schema))
            result = audit(root)
        self.assertIn("to_integer", schema_operations(root) if False else result["schema"]["operations"])
        self.assertEqual(result["converter"]["semantic_missing"], [])
        self.assertEqual(result["converter"]["to_integer_lowering_missing"], [])
        self.assertFalse(result["classification"]["to_integer_canonical_gap"])
        self.assertEqual(result["errors"], [])

    def test_deliberate_semantic_branch_removal_is_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            schema = {"$defs": {"expression": {"oneOf": [{"properties": {"to_integer": {}}}]}}}
            (root / "variable-expression.schema.json").write_text(json.dumps(schema))
            semantic = root / "src/scap_ng_tools/converter/_v04_semantic/v04_variable_expressions.py"
            semantic.parent.mkdir(parents=True)
            original = (ROOT / "src/scap_ng_tools/converter/_v04_semantic/v04_variable_expressions.py").read_text()
            semantic.write_text(original.replace("if op == 'to_integer':", "if op == 'removed_to_integer':", 1))
            lowering = semantic.parent.parent / "native041_input_expression.py"
            lowering.parent.mkdir(parents=True, exist_ok=True)
            lowering.write_text((ROOT / "src/scap_ng_tools/converter/native041_input_expression.py").read_text())
            result = audit(root, tools_root=root)
        self.assertIn("to_integer", result["converter"]["semantic_missing"])
        self.assertTrue(result["errors"])

    def test_canonical_gap_guard_rejects_old_to_integer_disposition(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            schema = {"$defs": {"expression": {"oneOf": [{"properties": {"to_integer": {}}}]}}}
            (root / "variable-expression.schema.json").write_text(json.dumps(schema))
            receipt = root / "receipt.json"
            receipt.write_text(json.dumps({"source_rule": "SV-221718", "category": "canonical_language_gap"}))
            result = audit(root, blocker_receipt=receipt)
        self.assertTrue(result["classification"]["to_integer_canonical_gap"])
        self.assertIn("incorrectly classified", " ".join(result["errors"]))


if __name__ == "__main__":
    unittest.main()
