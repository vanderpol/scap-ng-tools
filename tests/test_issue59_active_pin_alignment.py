"""Guard the active Issue #59 workflow against stale 0.4.0-era pins."""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CANONICAL_COMMIT = "2d983fcbd7b2367d567ca8ccc689a378d08905e4"
SCHEMA_DIGEST = "dc650646a24e727e68de242027cca3058683accc531f07bf6ace217609755b24"
WORKFLOW = ROOT / ".github/workflows/issue59-full65-rebuild.yml"


def load_script(name):
    path = ROOT / "scripts" / name
    spec = spec_from_file_location(name[:-3], path)
    module = module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ActiveIssue59Pins(unittest.TestCase):
    def test_full65_workflow_checks_out_and_passes_the_active_schema_pin(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(f"ref: {CANONICAL_COMMIT}", workflow)
        self.assertIn(f"--canonical-schema-commit {CANONICAL_COMMIT}", workflow)
        self.assertIn(f"--schema-aggregate-sha256 {SCHEMA_DIGEST}", workflow)
        self.assertNotIn("ref: aece827964c785be77b088c3c61255a2d07fd9a9", workflow)

    def test_active_rebuild_and_audit_helpers_emit_the_same_pin(self):
        rebuild = load_script("rebuild_issue59_full65.py")
        datatype = load_script("build_issue59_datatype_recovery.py")
        patterns = load_script("build_issue59_textfilecontent_patterns.py")
        remaining = load_script("build_issue59_remaining_collected_audit.py")
        self.assertEqual(rebuild.CANONICAL_SCHEMA_COMMIT, CANONICAL_COMMIT)
        self.assertEqual(rebuild.CANONICAL_SCHEMA_DIGEST, SCHEMA_DIGEST)
        self.assertEqual(datatype.CANONICAL_SCHEMA_COMMIT, CANONICAL_COMMIT)
        self.assertEqual(datatype.CANONICAL_SCHEMA_DIGEST, SCHEMA_DIGEST)
        self.assertEqual(patterns.SCHEMA_COMMIT, CANONICAL_COMMIT)
        self.assertEqual(patterns.SCHEMA_DIGEST, SCHEMA_DIGEST)
        self.assertEqual(remaining.SCHEMA_COMMIT, CANONICAL_COMMIT)
        self.assertEqual(remaining.SCHEMA_DIGEST, SCHEMA_DIGEST)


if __name__ == "__main__":
    unittest.main()
