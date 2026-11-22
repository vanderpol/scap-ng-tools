"""Adversarial guard for the source-backed full-65 blocker disposition."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs/evidence/issue83/full65-blocker-disposition-20261122.json"


class Full65BlockerDispositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
        cls.rows = cls.ledger["rows"]

    def test_pinned_denominator_and_disjoint_root_causes(self):
        self.assertEqual(self.ledger["format"],
                         "scap-ng-tools/issue83-full65-blocker-disposition/1")
        self.assertEqual(len(self.rows), 94)
        self.assertEqual(self.ledger["counts"]["by_disposition"],
                         {"deprecated-source": 83, "source-invalid": 11})
        self.assertEqual(self.ledger["counts"]["by_root_cause"], {
            "deprecated_windows_accesstoken": 66,
            "deprecated_windows_user": 5,
            "deprecated_windows_wmi_transitive_concat": 12,
            "source_invalid_cross_capability_reference": 9,
            "source_invalid_variable_result_datatype": 2,
        })
        self.assertEqual(len({row["source_rule"] for row in self.rows}), 94)
        self.assertNotIn("converter-defect", {
            row["disposition"] for row in self.rows})
        self.assertEqual(self.ledger["denominator"]["converted_to_blocked_regressions"], 0)

    def test_every_row_has_exact_source_identity_and_normative_basis(self):
        for row in self.rows:
            with self.subTest(rule=row["source_rule"]):
                for key in ("source_rule_sha256", "source_zip_sha256",
                            "source_xml_sha256", "definition_sha256"):
                    self.assertRegex(row[key], r"^[0-9a-f]{64}$")
                self.assertTrue(row["definition"])
                self.assertTrue(row["source_test_ids"])
                self.assertTrue(row["source_construct"])
                if row["disposition"] == "deprecated-source":
                    self.assertRegex(row["source_construct"]["deprecated_since"], r"^5\.")
                    self.assertTrue(row["source_construct"].get("replacement"))
                else:
                    self.assertEqual(row["disposition"], "source-invalid")

    def test_concat_rows_are_proven_deprecated_wmi_not_generic_concat_gaps(self):
        rows = [row for row in self.rows
                if row["root_cause"] == "deprecated_windows_wmi_transitive_concat"]
        self.assertEqual(len(rows), 12)
        for row in rows:
            construct = row["source_construct"]
            self.assertEqual(construct["name"], "wmi_object")
            self.assertEqual(construct["deprecated_since"], "5.7")
            self.assertTrue(construct["source_object_ids"])
            self.assertIn("concat", row["raw_diagnostic"])

    def test_source_invalid_rows_preserve_fail_closed_semantics(self):
        rows = [row for row in self.rows if row["disposition"] == "source-invalid"]
        self.assertEqual(len(rows), 11)
        cross = [row for row in rows
                 if row["root_cause"] == "source_invalid_cross_capability_reference"]
        self.assertEqual(len(cross), 9)
        self.assertTrue(all(row["source_construct"]["consumers"] for row in cross))
        casts = [row for row in rows
                  if row["root_cause"] == "source_invalid_variable_result_datatype"]
        self.assertEqual(len(casts), 2)
        self.assertEqual({row["source_construct"]["function_contract"]["function"]
                          for row in casts}, {"concat", "count"})
        self.assertTrue(all("do not add an implicit cast" in
                            row["source_construct"]["required_action"] for row in casts))

    def test_pins_are_the_merged_0_4_1_baseline(self):
        self.assertEqual(self.ledger["pins"], {
            "source_commit": "8c8e5dff860af6b1290ee9273a282db24278f8d5",
            "source_archive_sha256": "a780f91a487ceca1d03d23c0155e7fe612d55db44e27014f9de4e3adc6ce0097",
            "canonical_commit": "2d983fcbd7b2367d567ca8ccc689a378d08905e4",
            "schema_aggregate_sha256": "dc650646a24e727e68de242027cca3058683accc531f07bf6ace217609755b24",
            "converter_commit": "79ef6550e506903330024d5546df75c0a812f473",
        })


if __name__ == "__main__":
    unittest.main()
