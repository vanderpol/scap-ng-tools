"""Synthetic original-source identity and scope tests for the 65-ZIP rebuild driver."""
import copy
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/rebuild_issue59_full65.py"
spec = importlib.util.spec_from_file_location("rebuild_issue59_full65", SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def fixtures():
    old = []
    for i in range(7990):
        status = "converted" if i < 6479 else "blocked" if i < 6587 else "manual_only"
        old.append({"benchmark": "active-benchmark.zip", "source_rule": f"id-{i:04d}",
                    "status": status, "source_rule_sha256": "a" * 64})
    old.extend({"benchmark": "sql-benchmark.zip", "source_rule": f"sql-{i:04d}",
                "status": "intentionally_excluded", "source_rule_sha256": "b" * 64}
               for i in range(209))
    new = [dict(row, status=("blocked" if row["status"] == "intentionally_excluded"
                             else row["status"]), primary_blocker={"category": "semantic", "message": "sample"})
           for row in old]
    categories = {"active-benchmark.zip": "active", "sql-benchmark.zip": "owner_excluded_sql"}
    return old, new, categories


class Rebuild(unittest.TestCase):
    def test_same_source_active_denominator_and_excluded_sql(self):
        old, new, categories = fixtures()
        result = m.compare_rule_ids(old, new, categories)
        self.assertTrue(result["nonregression_pass"])
        self.assertEqual(result["newly_blocked_from_converted"], 0)
        self.assertEqual(result["candidate"], {"converted": 6479, "blocked": 108, "manual_only": 1403})
        self.assertEqual(len(result["blocked_rule_ids"]), 108)
        self.assertEqual(result["blocker_category_counts"], {"semantic": 108})

    def test_active_regression_is_hold_even_if_other_rules_recover(self):
        old, new, categories = fixtures()
        new[0]["status"] = "blocked"
        new[6479]["status"] = "converted"
        result = m.compare_rule_ids(old, new, categories)
        self.assertEqual(result["newly_blocked_from_converted"], 1)
        self.assertEqual(result["newly_converted_from_blocked"], 1)
        self.assertFalse(result["nonregression_pass"])

    def test_source_hash_and_missing_rule_id_fail_closed(self):
        old, new, categories = fixtures()
        changed = copy.deepcopy(new)
        changed[0]["source_rule_sha256"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "source Rule XML identity drift"):
            m.compare_rule_ids(old, changed, categories)
        with self.assertRaisesRegex(ValueError, "Rule IDs differ"):
            m.compare_rule_ids(old, new[:-1], categories)

    def test_sql_coverage_never_enters_active_admission(self):
        old, new, categories = fixtures()
        new[-1]["status"] = "converted"
        result = m.compare_rule_ids(old, new, categories)
        self.assertTrue(result["nonregression_pass"])
        self.assertEqual(result["candidate"]["converted"], 6479)


if __name__ == "__main__":
    unittest.main()
