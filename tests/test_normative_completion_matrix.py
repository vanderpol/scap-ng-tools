"""Tests for the conservative source-language completion normalizer."""
import json
from pathlib import Path
import unittest

from scripts.build_normative_completion_matrix import build, compact, markdown


class NormativeCompletionMatrixTests(unittest.TestCase):
    def crosswalk(self):
        return {
            "format": "scap-ng-tools/issue83-source-crosswalk/1",
            "source": {"commit": "source-pin"},
            "oval_schema_inventory": {
                "source_commit_expected": "oval-pin",
                "summary": {"canonical_mapping_commit": "canonical-pin",
                            "declarations": 4, "canonical_mapping_rows": 1},
                "grammar_rows": [
                    {"source_kind": "element", "source_path": "/element[0]",
                     "schema_file": "windows-definitions-schema.xsd",
                     "source_qname": "{urn:test}mapped", "source_name": "mapped",
                     "source_member_names": ["object", "state"],
                     "canonical_mapping_candidates": [{
                         "capability": "windows.test", "mapping_file": "x.json",
                         "source_role": "test", "source_language": "OVAL 5.12.3",
                         "schema_file": "windows-definitions-schema.xsd",
                         "source_namespace": "urn:test", "source_name": "mapped",
                         "mapping_status": "declared_unproven",
                         "converter_proof": "not_run",
                         "runtime_equivalence": "not_proved",
                     }]},
                    {"source_kind": "element", "source_path": "/element[0]",
                     "schema_file": "linux-definitions-schema.xsd",
                     "source_qname": "{urn:test}deprecated", "source_name": "deprecated",
                     "deprecation": [{"version": "5.12"}],
                     "disposition": "deprecated_migration"},
                    {"source_kind": "element", "source_path": "/element[0]",
                     "schema_file": "linux-definitions-schema.xsd",
                     "source_qname": "{urn:test}unmapped", "source_name": "unmapped",
                     "source_member_names": ["value"]},
                    {"source_kind": "element", "source_path": "/element/nested",
                     "schema_file": "linux-definitions-schema.xsd",
                     "source_qname": "{urn:test}ignored", "source_name": "ignored"},
                ],
            },
        }

    def test_normalizes_top_level_features_without_promoting_proof(self):
        matrix = build(self.crosswalk(), source_sha256="crosswalk-hash",
                       source_path="/external/crosswalk.json")
        self.assertEqual(matrix["counts"]["distinct_top_level_features"], 3)
        self.assertEqual(matrix["counts"]["by_classification"], {
            "deprecated": 1, "mapped_unproven": 1,
            "unmapped_source_feature": 1,
        })
        self.assertEqual(matrix["features"][0]["semantic_proof"], "not_proved")
        self.assertEqual(matrix["features"][0]["ri_runtime"], "not_run")
        self.assertEqual(matrix["source"]["oval_schema_commit"], "oval-pin")

    def test_dispositions_cover_non_top_level_grammar_rows(self):
        crosswalk = self.crosswalk()
        crosswalk["oval_schema_inventory"]["grammar_rows"].extend([
            {"source_kind": "attribute", "source_path": "/element[0]/attribute[0]",
             "schema_file": "windows-definitions-schema.xsd",
             "source_qname": "{urn:test}mapped-attribute",
             "canonical_mapping_candidates": [{"capability": "windows.test"}]},
            {"source_kind": "assert", "source_path": "/element[0]/assert[0]",
             "schema_file": "windows-definitions-schema.xsd",
             "source_qname": "{urn:test}unmapped-assert"},
            {"source_kind": "enumeration", "source_path": "/element[0]/enum[0]",
             "schema_file": "windows-definitions-schema.xsd",
             "source_qname": "{urn:test}deprecated-enum",
             "deprecation": [{"version": "5.12"}]},
        ])
        matrix = build(crosswalk, source_sha256="hash", source_path="crosswalk")
        grammar = matrix["grammar_inventory"]
        self.assertEqual(grammar["rows"], 7)
        self.assertEqual(grammar["by_source_kind"]["attribute"],
                         {"mapped_unproven": 1})
        self.assertEqual(grammar["by_source_kind"]["assert"],
                         {"semantic_constraint_unproven": 1})
        self.assertEqual(grammar["by_source_kind"]["enumeration"],
                         {"deprecated": 1})
        self.assertIn("Schematron rows are semantic constraints", grammar["policy"])

    def test_duplicate_top_level_identity_is_rejected(self):
        crosswalk = self.crosswalk()
        duplicate = dict(crosswalk["oval_schema_inventory"]["grammar_rows"][0])
        crosswalk["oval_schema_inventory"]["grammar_rows"].append(duplicate)
        with self.assertRaisesRegex(ValueError, "duplicate top-level source identity"):
            build(crosswalk, source_sha256="hash", source_path="crosswalk")

    def test_top_level_identity_must_be_complete(self):
        crosswalk = self.crosswalk()
        crosswalk["oval_schema_inventory"]["grammar_rows"][0]["schema_file"] = ""
        with self.assertRaisesRegex(ValueError, "missing schema/QName identity"):
            build(crosswalk, source_sha256="hash", source_path="crosswalk")

    def test_markdown_reports_holds_not_conversion_success(self):
        text = markdown(build(self.crosswalk(), source_sha256="hash",
                              source_path="crosswalk"))
        self.assertIn("Mapped, unproven", text)
        self.assertIn("Unmapped hold", text)
        self.assertIn("does not prove", text)

    def test_compact_external_hash_is_reproducible(self):
        matrix = build(self.crosswalk(), source_sha256="hash",
                       source_path="crosswalk")
        compacted = compact(matrix)
        self.assertNotIn("features", compacted)
        self.assertEqual(compacted["features_external"]["count"], 3)
        self.assertEqual(len(compacted["features_external"]["sha256"]), 64)
        self.assertEqual(matrix["counts"]["distinct_top_level_features"], 3)


if __name__ == "__main__":
    unittest.main()
