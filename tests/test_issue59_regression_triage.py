"""Source-ID-preserving Issue #59 regression triage receipts."""
import unittest

from scripts.triage_issue59_regressions import build_inventory, family_for


def receipt(message="ambiguous allowed datatype from collected field"):
    return {
        "format": "scap-ng-0.4.1-source-rule-identity-rebuild/1",
        "scanner_equivalent": False,
        "owner_scope": {
            "active": 7990, "owner_excluded_sql": 209,
            "historical_windows_2012": 693,
        },
        "newly_blocked_from_converted": 1,
        "source_commit": "pinned-source",
        "schema_aggregate_sha256": "pinned-schema",
        "regression_ids": [{
            "benchmark": "RHEL9.zip", "source_rule": "SV-example",
            "source_rule_sha256": "original-xml-sha",
            "from": "converted", "to": "blocked",
            "primary_blocker": message, "blocker_category": "schema-semantic",
            "original_proof_level": "authoring_validated",
            "new_proof_level": "none",
        }],
    }


class RegressionTriage(unittest.TestCase):
    def test_preserves_exact_id_provenance_and_refuses_type_invention(self):
        rows, summary = build_inventory(receipt())
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual((row["benchmark"], row["source_rule"]), ("RHEL9.zip", "SV-example"))
        self.assertEqual(row["source_rule_sha256"], "original-xml-sha")
        self.assertEqual(row["type_family"], "collected_field")
        self.assertEqual(row["source_value_domain"], "UNDETERMINED")
        self.assertEqual(row["explicit_native_mapping"], "UNDETERMINED")
        self.assertEqual(row["oracle_status"], "NOT_RUN")
        self.assertIs(summary["scanner_equivalent"], False)
        self.assertEqual(summary["regressions"], 1)

    def test_function_type_diagnostics_are_not_conflated(self):
        for message, expected in (
            ("unique requires one scalar datatype", "unique"),
            ("split requires an unambiguous string input", "split"),
            ("substring requires unambiguous string input", "substring"),
            ("unsupported property", "unclassified"),
        ):
            with self.subTest(message=message):
                self.assertEqual(family_for(message), expected)

    def test_rejects_duplicate_source_rule_ids(self):
        data = receipt()
        data["regression_ids"].append(data["regression_ids"][0].copy())
        data["newly_blocked_from_converted"] = 2
        with self.assertRaisesRegex(ValueError, "duplicate source Rule identity"):
            build_inventory(data)

    def test_rejects_unexpected_scope_or_proof_claim(self):
        for mutation in ("scope", "scanner", "count", "transition", "identity"):
            with self.subTest(mutation=mutation):
                data = receipt()
                if mutation == "scope":
                    data["owner_scope"]["active"] = 7991
                elif mutation == "scanner":
                    data["scanner_equivalent"] = True
                elif mutation == "count":
                    data["newly_blocked_from_converted"] = 2
                elif mutation == "transition":
                    data["regression_ids"][0]["to"] = "manual_only"
                else:
                    data["regression_ids"][0]["source_rule"] = ""
                with self.assertRaises(ValueError):
                    build_inventory(data)


if __name__ == "__main__":
    unittest.main()
