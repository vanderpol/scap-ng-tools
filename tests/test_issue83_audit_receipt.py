"""Focused tests for the compact Issue #83 source audit receipt."""
from pathlib import Path
import json
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_issue83_audit_receipt as audit  # noqa: E402


class Issue83AuditReceiptTests(unittest.TestCase):
    def crosswalk(self):
        return {
            "format": "scap-ng-tools/issue83-source-crosswalk/1",
            "source": {
                "commit": "content",
                "expected_archives": 1,
                "archive_set_sha256": "archive",
                "xccdf_schema": {"sha256": "xccdf", "url": "https://example/xsd"},
            },
            "summary": {
                "source_rules": 2,
                "rules_with_requires_or_conflicts": 0,
                "requires_rows": 0,
                "conflicts_rows": 0,
                "groups_with_requires_or_conflicts": 0,
                "group_requires_rows": 0,
                "group_conflicts_rows": 0,
                "xccdf_metadata_rule_field_counts": {"fix": 2},
                "xccdf_metadata_element_counts": {"fix": 2},
                "disa_description_rule_field_counts": {"VulnDiscussion": 2},
                "disa_description_nonempty_rule_field_counts": {"VulnDiscussion": 2},
                "malformed_publisher_payload_rules": [],
            },
            "oval_schema_inventory": {
                "source_commit_expected": "oval",
                "summary": {
                    "schema_files": 1,
                    "schema_manifest_files": 1,
                    "definition_schema_files": 1,
                    "system_characteristics_schema_files": 0,
                    "declarations": 2,
                    "grammar_rows": 3,
                    "canonical_mapping_rows": 1,
                    "grammar_rows_with_mapping": 1,
                    "native_mapping_status": {"unproven": 2},
                    "official_deprecation_annotations": 0,
                    "declarations_with_deprecated_members": 0,
                    "schema_dependencies": 0,
                    "unresolved_schema_dependencies": 0,
                    "schema_references": 0,
                    "resolved_schema_references": 0,
                    "unresolved_schema_references": 0,
                    "schematron_rows": 1,
                    "schematron_assertions": 1,
                    "schematron_reports": 0,
                    "prose_rows": 1,
                    "evaluation_documentation_rows": 1,
                    "evaluation_chart_rows": 0,
                    "schematron_test_feature_counts": {"equality": 1},
                },
            },
        }

    def test_build_is_compact_and_preserves_proof_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "crosswalk.json"
            path.write_text(json.dumps(self.crosswalk()), encoding="utf-8")
            result = audit.build(path, None, converter_commit="tools",
                                 canonical_commit="canonical",
                                 canonical_schema_sha256="schema",
                                 oval_commit="oval")
        self.assertEqual(result["source"]["archive_count"], 1)
        self.assertEqual(result["xccdf"]["metadata_element_counts"], {"fix": 2})
        self.assertEqual(result["oval_schema_inventory"]["schematron_assertions"], 1)
        self.assertTrue(result["proof_limits"])
        self.assertEqual(result["candidate_qualification"], None)

    def test_mapping_join_rejects_namespace_drift(self):
        oval = {
            "grammar_rows": [{
                "schema_file": "esx-definitions-schema.xsd",
                "source_qname": "{http://oval.mitre.org/XMLSchema/oval-definitions-5#esx}host_account_test",
                "source_name": "host_account_test",
            }],
            "canonical_mappings": [{
                "capability": "esx.host_account",
                "mapping_file": "experimental/esx.host_account.json",
                "source_role": "test",
                "source_language": "OVAL 6.0 new tests only",
                "source_upstream_commit": "upstream",
                "source_definitions_schema": "third_party/oval-6.0-new-tests/esx-definitions-schema.xsd",
                "source_schema": "esx-definitions-schema.xsd",
                "source_namespace": "urn:oval:v6:definitions:esx",
                "source_name": "host_account_test",
            }],
        }
        result = audit._mapping_join_diagnostics(oval)
        self.assertEqual(result["exact_grammar_join_rows"], 0)
        self.assertEqual(result["unmatched_by_reason"], {"mapping_source_version_out_of_scope": 1})
        self.assertEqual(result["unmatched"][0]["source_language"], "OVAL 6.0 new tests only")
        self.assertEqual(result["unmatched"][0]["source_namespace"],
                         "urn:oval:v6:definitions:esx")

    def test_candidate_holds_keep_source_identity_and_class(self):
        candidate = {
            "summary": {"blocked_tests": 1},
            "source": {"commit": "source"},
            "converter_commit": "tools",
            "qualification": "not_run",
            "families": {"tests": {"windows": {
                "outcomes": {"blocked": 1},
                "failure_classes": {"schema_or_validation_failure": 1},
            }}},
            "blocked_by_source": {"tests": [{
                "failure_class": "schema_or_validation_failure",
                "diagnostic": "traversal rejected",
                "source_path": "windows/test.xml",
                "source_sha256": "source-sha",
                "ids": ["tst:1"],
            }]},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crosswalk = root / "crosswalk.json"
            candidate_path = root / "candidate.json"
            crosswalk.write_text(json.dumps(self.crosswalk()), encoding="utf-8")
            candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
            result = audit.build(crosswalk, candidate_path, converter_commit="tools",
                                 canonical_commit="canonical",
                                 canonical_schema_sha256="schema",
                                 oval_commit="oval")
        hold = result["candidate_qualification"]["source_linked_holds"][0]
        self.assertEqual(hold["source_path"], "windows/test.xml")
        self.assertEqual(hold["source_ids"], ["tst:1"])
        self.assertEqual(hold["failure_class"], "schema_or_validation_failure")
        self.assertEqual(result["candidate_qualification"]["execution"], "not_run")


if __name__ == "__main__":
    unittest.main()
