"""Unit tests for the bounded independent OpenSCAP ledger harness."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import qualify_openscap_oval as qualification  # noqa: E402


class OpenSCAPQualificationTests(unittest.TestCase):
    def test_safe_name_is_deterministic_and_not_a_path(self):
        name = qualification.safe_name(Path("unix") / "nested" / "a.xml")
        self.assertEqual(name, qualification.safe_name(Path("unix") / "nested" / "a.xml"))
        self.assertNotIn("/", name)
        self.assertTrue(name.endswith("-a.xml"))

    def test_parse_results_extracts_only_definition_outcomes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "results.xml"
            path.write_text(
                '<results><definitions><definition definition_id="oval:def:1" result="true" />'
                '<definition definition_id="oval:def:2" result="unknown"><item secret="no" /></definition>'
                '</definitions></results>', encoding="utf-8")
            self.assertEqual(
                qualification.parse_results(path),
                [{"definition_id": "oval:def:1", "result": "true"},
                 {"definition_id": "oval:def:2", "result": "unknown"}],
            )

    def test_summary_preserves_outcome_names_and_omits_zeroes(self):
        result = qualification.summarize_outcomes([
            {"definition_id": "a", "result": "false"},
            {"definition_id": "b", "result": "false"},
            {"definition_id": "c", "result": "unknown"},
        ])
        self.assertEqual(result, {"false": 2, "unknown": 1})

    def test_diagnostic_is_bounded_and_replaces_external_roots(self):
        text = "/tmp/private/path " + ("x" * 5000)
        result = qualification.sanitize_diagnostic(text, (("/tmp/private", "<external>"),))
        self.assertLessEqual(len(result), 1000)
        self.assertNotIn("/tmp/private", result)
        self.assertNotIn("/home/", result)
        self.assertNotIn("/proc/", result)


if __name__ == "__main__":
    unittest.main()
