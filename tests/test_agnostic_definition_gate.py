"""Definition gate checks only observed Assessment outcomes, never Test counts."""
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "agnostic_definition_gate", ROOT / "tools/check_agnostic_definition_gate.py"
)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class DefinitionQualificationGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((
            ROOT / "docs/qualification/agnostic-self-assertion/expected-definitions.json"
        ).read_text())

    def rows(self):
        return [{
            "family": "agnostic",
            "source_id": item["source_definition_id"],
            "source_xml": item["source_path"],
            "source_xml_sha256": item["source_sha256"],
            "execution_status": "executed",
            "actual_outcome": item["expected_outcome"],
        } for item in self.manifest["definitions"]]

    def test_expected_manifest_contains_all_46_source_definitions(self):
        entries = self.manifest["definitions"]
        self.assertEqual(len(entries), 46)
        self.assertEqual(len({e["source_definition_id"] for e in entries}), 46)
        self.assertEqual(sum(e["expected_outcome"] == "true" for e in entries), 44)
        self.assertEqual(sum(e["expected_outcome"] == "false" for e in entries), 1)
        self.assertEqual(sum(e["expected_outcome"] == "unknown" for e in entries), 1)
        self.assertEqual(gate.compare(self.manifest, self.rows())["status"], "PASS")

    def test_no_waiver_for_unknown_or_blocked_definitions(self):
        rows = self.rows()
        for row in rows:
            if row["source_id"] == "oval:org.mitre.oval.test:def:67":
                row["actual_outcome"] = "unknown"
            if row["source_id"] == "oval:navy.navwar.niwcatlantic.scc:def:38":
                row["execution_status"] = "blocked"
                row["actual_outcome"] = ""
        checked = gate.compare(self.manifest, rows)
        self.assertEqual(checked["status"], "FAIL")
        self.assertEqual(checked["verified_expected_outcomes"], 44)
        self.assertEqual(len(checked["problems"]), 2)

    def test_negation_and_intentional_unknown_are_preserved(self):
        rows = self.rows()
        for row in rows:
            if row["source_id"] in {
                "oval:org.mitre.oval.test:def:997",
                "oval:org.mitre.oval.test:def:337",
            }:
                row["actual_outcome"] = "true"
        checked = gate.compare(self.manifest, rows)
        self.assertEqual(checked["status"], "FAIL")
        self.assertEqual(checked["verified_expected_outcomes"], 44)

    def test_duplicate_missing_and_source_sha_drift_are_fatal(self):
        rows = self.rows()
        rows.pop()
        rows[0]["source_xml_sha256"] = "0" * 64
        rows.append(dict(rows[0]))
        checked = gate.compare(self.manifest, rows)
        self.assertEqual(checked["status"], "FAIL")
        self.assertEqual(len(checked["problems"]), 3)


if __name__ == "__main__":
    unittest.main()
