"""Owner scope and immutable same-source admission evidence gates for 0.4.1."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "scripts/audit_issue59_active_scope.py"
SPEC = importlib.util.spec_from_file_location("issue59_active_scope", AUDIT)
audit_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_module)


class OwnerScopedAdmissionAudit(unittest.TestCase):
    def test_active_59_and_owner_excluded_six_reconcile(self):
        result = audit_module.audit()
        active = result["scope"]["active"]
        sql = result["scope"]["excluded_sql"]
        old = result["scope"]["historical_windows_2012"]
        self.assertEqual((active["benchmarks"], active["old"]["source_rules"]), (59, 7990))
        self.assertEqual(active["old"]["converted"], 6479)
        self.assertEqual(active["old"]["blocked"], 108)
        self.assertEqual(active["old"]["manual_only"], 1403)
        self.assertEqual((sql["benchmarks"], sql["old"]["source_rules"]), (4, 209))
        self.assertEqual(sql["old"]["intentionally_excluded"], 209)
        self.assertEqual((old["benchmarks"], old["old"]["source_rules"]), (2, 693))
        self.assertEqual(sum(group["old"]["source_rules"] for group in result["scope"].values()), 8892)
        self.assertEqual(sum(group["new"]["source_rules"] for group in result["scope"].values()), 8892)
        self.assertEqual(result["scanner_equivalence"], "NOT_PROVED")
        self.assertIn("NOT_PROVED", result["rule_id_equivalence"])

    def test_known_regression_is_visible_without_approving_it(self):
        result = audit_module.audit()
        active = result["scope"]["active"]
        self.assertEqual(active["new"]["converted"], 6308)
        self.assertEqual(active["new"]["blocked"], 279)
        self.assertEqual(active["new"]["manual_only"], 1403)
        self.assertEqual(result["regression"]["net_lost_converted"], 171)
        self.assertEqual(result["regression"]["gross_lost_converted"], 174)
        self.assertEqual(result["regression"]["gross_gained_converted"], 3)
        self.assertFalse(result["nonregression_gate"]["pass"])
        self.assertEqual(result["scope"]["excluded_sql"]["new"]["converted"], 7)
        # This is a time-stamped regression receipt, not a release acceptance
        # baseline: update with a fresh same-source rebuild when recovery lands.

    def test_cli_reports_and_enforce_mode_holds(self):
        show = subprocess.run([sys.executable, str(AUDIT)],
                              capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(show.returncode, 0, show.stderr)
        self.assertEqual(json.loads(show.stdout)["scope"]["active"]["benchmarks"], 59)
        enforce = subprocess.run([sys.executable, str(AUDIT), "--enforce-nonregression"],
                                 capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(enforce.returncode, 1)
        self.assertIn("HOLD", enforce.stderr)

    def test_source_hash_drift_is_fatal(self):
        crosswalk = json.loads(audit_module.CROSSWALK.read_text())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "crosswalk.json"
            crosswalk["benchmarks"][0]["source_sha256"] = "0" * 64
            path.write_text(json.dumps(crosswalk), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "same-source identity drift"):
                audit_module.audit(crosswalk_path=path)

    def test_unaccounted_or_reclassified_rule_is_fatal(self):
        crosswalk = json.loads(audit_module.CROSSWALK.read_text())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "crosswalk.json"
            crosswalk["benchmarks"][0]["new_0_4_1"]["converted"] -= 1
            path.write_text(json.dumps(crosswalk), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "admission evidence differs"):
                audit_module.audit(crosswalk_path=path)


if __name__ == "__main__":
    unittest.main()
