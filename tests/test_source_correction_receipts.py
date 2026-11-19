"""Integrity checks for compact, source-linked correction receipts."""
from __future__ import annotations

import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class SourceCorrectionReceiptTests(unittest.TestCase):
    def load(self, name: str) -> dict:
        path = ROOT / "docs" / "evidence" / "issue83" / name
        with path.open(encoding="utf-8") as stream:
            return json.load(stream)

    def test_nvram_pr19_receipt_preserves_identity_and_native_parity(self):
        receipt = self.load("nvram-pr19-focused-qualification.json")
        source = receipt["source"]
        conversion = receipt["conversion"]

        self.assertEqual(receipt["format"], "scap-ng-tools/issue83-source-correction-focused/1")
        self.assertEqual(source["repository"], "OVAL-Community/SCAP-Self-Assertion")
        self.assertEqual(source["path"], "SCAP_1.4/OVAL_Test_Content/macos/macos-def_nvram512_test.xml")
        self.assertEqual(source["definition_id"], "oval:org.mitre.oval.test:def:448")
        self.assertEqual(source["corrected_pr"], 19)
        self.assertTrue(source["source_commit_blob_verified"])
        self.assertTrue(conversion["base_schema_validated"])
        self.assertTrue(conversion["corrected_schema_validated"])
        self.assertTrue(conversion["native_assessment_bytes_identical"])
        self.assertTrue(conversion["source_trace_differs_as_expected"])
        self.assertEqual(conversion["independent_runtime_equivalence"], "not_proved")
        self.assertTrue(conversion["current_replay_verified"])
        self.assertEqual(conversion["converter_commit"],
                         "94156d57614159c767ed26717c496207c6d048ce")
        self.assertRegex(conversion["base_source_trace_sha256"], HEX64)
        self.assertRegex(conversion["corrected_source_trace_sha256"], HEX64)

        for key in ("base_sha256", "corrected_sha256"):
            self.assertRegex(source[key], HEX64)
        self.assertRegex(conversion["base_assessment_sha256"], HEX64)
        self.assertEqual(
            conversion["base_assessment_sha256"],
            conversion["corrected_assessment_sha256"],
        )
        self.assertEqual(
            len(source["affected_test_ids"]), 3,
        )
        self.assertIn("oval:org.mitre.oval.test:obj:754", source["affected_objects"])
        self.assertEqual(len(source["affected_states"]), 3)

    def test_agnostic_merge_pr7_replay_refreshes_current_converter_pin(self):
        receipt = self.load("merge-pr7-focused-qualification.json")
        conversion = receipt["conversion"]
        self.assertEqual(receipt["source"]["corrected_pr"], 7)
        self.assertEqual(receipt["pins"]["tools_commit"],
                         "26fc48e13752922627c59719a53fc64db60d32ce")
        self.assertTrue(conversion["current_replay_verified"])
        self.assertTrue(conversion["semantic_projection_equal"])
        self.assertEqual(conversion["base_assessment_sha256"],
                         "4cbbc6644c1de30afac52eb7e928bf9a56dbfc907f65cc12d9133d568235d3f2")
        self.assertEqual(conversion["corrected_assessment_sha256"],
                         "9a863c12efd97ae2ff46cdf5e4ef05d77ff182288aa7a2099f2036bf9c748788")
        self.assertRegex(conversion["base_source_trace_sha256"], HEX64)
        self.assertRegex(conversion["corrected_source_trace_sha256"], HEX64)
        self.assertNotEqual(conversion["base_source_trace_sha256"],
                            conversion["corrected_source_trace_sha256"])

    def test_nvram_pr8_replay_keeps_version_hold_and_recovery_separate(self):
        receipt = self.load("macos-nvram-followup.json")
        self.assertEqual(receipt["format"], "scap-ng-tools/issue83-macos-nvram-followup/1")
        self.assertEqual(receipt["converter_commit"],
                         "26fc48e13752922627c59719a53fc64db60d32ce")
        self.assertEqual(receipt["definition_id"], "oval:org.mitre.oval.test:def:448")
        source = receipt["source"]
        self.assertEqual(source["original_commit"],
                         "e3538595c5083b9c34d937a81d319234df9bbfaa")
        self.assertEqual(source["candidate_commit"],
                         "9d3ae629da96bf8b15730a5c6ac274cf29fcd7d5")
        self.assertEqual(source["original_sha256"],
                         "de4dcd4ba3e81f63916db722c462aff48e1702f414b33879c4497d8421bd70cd")
        self.assertEqual(source["candidate_sha256"],
                         "15ab1e122b7b58d40c1b81dc71a512a9e55b01c4ce0aeaed35e85160aec0a2ef")
        self.assertEqual(receipt["before"]["status"], "blocked")
        self.assertEqual(receipt["before"]["failure_class"], "source_version_hold")
        self.assertEqual(receipt["before"]["diagnostic"],
                         "unsupported standalone source OVAL version: '5.10.1'")
        self.assertEqual(receipt["after"]["status"], "CONVERTED_UNVERIFIED")
        self.assertTrue(receipt["after"]["schema_validated"])
        self.assertFalse(receipt["after"]["runtime_execution"])
        self.assertFalse(receipt["after"]["independent_oval_equivalence"])
        self.assertEqual(receipt["output"]["files"]["source-trace.json"]["sha256"],
                         "012f045fcb8bd5a76267384482026b6aa4805f11c31676686ad9bd5f84923e1f")
        self.assertEqual(receipt["reproduction"]["corrected_result"]["assessment_sha256"],
                         receipt["output"]["files"]["assessment.json"]["sha256"])

    def test_exploratory_openscap_receipt_keeps_legacy_limits_explicit(self):
        receipt = self.load("openscap-exploratory-pr6-pr16.json")
        self.assertEqual(receipt["tool"]["version"], "1.3.9")
        self.assertEqual(receipt["tool"]["validation_mode"], "--skip-valid")
        self.assertIn("not authoritative", receipt["tool"]["authority"])
        self.assertEqual(len(receipt["cases"]), 2)
        for case in receipt["cases"]:
            self.assertIn(case["base_result"], {"true", "false", "unknown", "error"})
            self.assertIn(case["corrected_result"], {"true", "false", "unknown", "error"})
            self.assertRegex(case["base_results_sha256"], HEX64)
            self.assertRegex(case["corrected_results_sha256"], HEX64)
        self.assertTrue(any("expected outcome" in x.lower() for x in receipt["limitations"]))

    def test_pr20_pr21_focused_receipt_keeps_content_and_canonical_holds_separate(self):
        receipt = self.load("source-correction-pr20-pr21-focused-20261119.json")
        self.assertEqual(receipt["pins"]["ios_candidate_source_commit"],
                         "34d471b20ecf110d19b04396645e891cfb772487")
        self.assertEqual(receipt["pins"]["junos_candidate_source_commit"],
                         "9e079baea4432b3babff5429ca726c281872de1f")
        ios = next(row for row in receipt["source_corrections"] if row["pull_request"] == 20)
        self.assertEqual(ios["replay"]["baseline_failure_class"], "deprecated_source_construct")
        self.assertEqual(ios["replay"]["candidate_failure_class"], "canonical_capability_gap")
        self.assertEqual(ios["replay"]["candidate_semantic_disposition"], "canonical_capability_gap")
        self.assertEqual(len(ios["replay"]["candidate_manifest_sha256"]), 64)
        self.assertEqual(len(ios["affected_test_ids"]), 4)
        junos = next(row for row in receipt["source_corrections"] if row["pull_request"] == 21)
        self.assertIsNone(junos["candidate_source_sha256"])
        self.assertEqual(junos["replay"]["candidate_status"], "removed_by_content_correction")
        self.assertEqual(receipt["summary"]["ios_definitions_recovered"], 0)
        self.assertEqual(receipt["summary"]["junos_definitions_removed_by_correction"], 1)

    def test_pr11_batch_replay_excludes_removed_deprecated_tests(self):
        receipt = self.load("source-correction-batch-20261119.json")
        case = next(row for row in receipt["cases"] if row["pull_request"] == 11)
        self.assertEqual(case["source_test_ids"], [
            "oval:org.mitre.oval.test:tst:664",
            "oval:org.mitre.oval.test:tst:1289",
            "oval:org.mitre.oval.test:tst:525",
            "oval:org.mitre.oval.test:tst:1006",
            "oval:org.mitre.oval.test:tst:680",
        ])
        self.assertEqual(case["base_failure_class"], "deprecated_source_construct")
        self.assertEqual(case["corrected_failure_class"], "canonical_traversal_schema_hold")
        self.assertNotIn("oval:org.mitre.oval.test:tst:1474", case["source_test_ids"])
        self.assertNotIn("oval:org.mitre.oval.test:tst:1141", case["source_test_ids"])

    def test_existing_deprecated_followups_have_exact_blob_provenance(self):
        names = [
            "macos-keychain-deprecated-object-followup.json",
            "windows-audit-deprecated-field-followup.json",
            "windows-object-notes-followup.json",
            "windows-registry-group-deprecated-followup.json",
        ]
        for name in names:
            with self.subTest(name=name):
                source = self.load(name)["source"]
                self.assertTrue(source["source_commit_blob_verified"])
                self.assertRegex(source["baseline_sha256"], HEX64)
                self.assertRegex(source["candidate_sha256"], HEX64)

    def test_windows_pr11_preserves_downward_traversal_schema_hold(self):
        receipt = self.load("windows-registry-group-deprecated-followup.json")
        source = receipt["source"]
        candidate = receipt["conversion"]["candidate"]
        self.assertEqual(len(source["retained_tests"]), 5)
        self.assertEqual(source["definition_version_transition"], {"baseline": "1", "candidate": "2"})
        self.assertEqual(source["removed_objects"], [
            "oval:org.mitre.oval.test:obj:305",
            "oval:org.mitre.oval.test:obj:1080",
        ])
        self.assertEqual(source["removed_states"], [
            "oval:org.mitre.oval.test:ste:1091",
            "oval:org.mitre.oval.test:ste:1153",
        ])
        self.assertEqual(
            {row["test_id"] for row in source["retained_tests"]},
            {
                "oval:org.mitre.oval.test:tst:664",
                "oval:org.mitre.oval.test:tst:1289",
                "oval:org.mitre.oval.test:tst:525",
                "oval:org.mitre.oval.test:tst:1006",
                "oval:org.mitre.oval.test:tst:680",
            },
        )
        for row in source["retained_tests"]:
            self.assertRegex(row["object_source_xml_sha256"], HEX64)
            self.assertRegex(row["test_source_xml_sha256"], HEX64)
        self.assertEqual(candidate["schema_evidence"]["schema_object_pointer"],
                         "native-selector.schema.json#/$defs/windows_regkeyeffectiverights_object/oneOf/1")
        self.assertNotIn("traversal", candidate["schema_evidence"]["schema_allowed_properties"])
        self.assertEqual(candidate["schema_evidence"]["canonical_gap"],
                         "valid downward OVAL recursion is described by the mapping but is not representable by the pinned native object schema")
        self.assertFalse(candidate["runtime_execution"])
        self.assertFalse(candidate["independent_oval_equivalence"])

    def test_solaris_pr15_receipt_preserves_deprecated_removals(self):
        receipt = self.load("solaris-followup.json")
        correction = receipt["source_correction"]
        self.assertEqual(correction["pull_request"], 15)
        self.assertTrue(correction["source_commit_blob_verified"])
        self.assertEqual(len(correction["removed_paths"]), 2)
        self.assertEqual(receipt["before"]["blocked"], 12)
        self.assertEqual(receipt["after"]["blocked"], 9)
        self.assertFalse(receipt["qualification"]["runtime_execution"])
        self.assertFalse(receipt["qualification"]["independent_oval_equivalence"])
        self.assertTrue(receipt["qualification"]["current_replay_verified"])
        self.assertEqual(receipt["pins"]["converter_commit"], "e9ef68668625aa724fe994c82ebba364f4b90359")
        self.assertRegex(receipt["recovered"][0]["trace_sha256"], HEX64)
        self.assertTrue(receipt["recovered"][0]["current_replay_verified"])

    def test_existing_source_correction_batch_keeps_exact_transitions(self):
        receipt = self.load("source-correction-batch-20261119.json")
        self.assertEqual(receipt["summary"]["cases"], 13)
        self.assertEqual(receipt["summary"]["corrected_converted"], 10)
        self.assertEqual(receipt["summary"]["corrected_blocked"], 1)
        self.assertEqual(receipt["summary"]["removed_by_correction"], 2)
        self.assertEqual(receipt["summary"]["transitions"]["blocked->CONVERTED_UNVERIFIED"], 6)
        for case in receipt["cases"]:
            self.assertRegex(case["base_source_sha256"], HEX64)
            self.assertIn(case["base_status"], {"blocked", "CONVERTED_UNVERIFIED"})
            if case["corrected_status"] == "CONVERTED_UNVERIFIED":
                self.assertRegex(case["corrected_source_sha256"], HEX64)
                self.assertRegex(case["corrected_assessment_sha256"], HEX64)
                self.assertRegex(case["corrected_trace_sha256"], HEX64)

    def test_macos_pr12_replay_replaces_deprecated_environment_object(self):
        receipt = self.load("macos-keychain-deprecated-object-followup.json")
        conversion = receipt["conversion"]
        self.assertTrue(conversion["current_replay_verified"])
        self.assertEqual(conversion["base_returncode"], 1)
        self.assertEqual(conversion["candidate_returncode"], 0)
        self.assertRegex(conversion["candidate"]["source_trace_sha256"], HEX64)
        self.assertEqual(conversion["candidate"]["assessment_sha256"],
                         "d6ac8d4ac9b5c1c136fe12d5420bc4bd13ae1acb9d2c9b4185ed9a9a64cce6b3")

    def test_windows_policy_pr5_replay_proves_source_hold_recovery(self):
        receipt = self.load("windows-policy-pr5-replay-20261119.json")
        self.assertEqual(receipt["source"]["correction_pr"], 5)
        self.assertEqual(len(receipt["cases"]), 2)
        for case in receipt["cases"]:
            self.assertEqual(case["base_status"], "blocked")
            self.assertEqual(case["base_failure_class"], "source_typed_literal_invalid")
            self.assertEqual(case["corrected_status"], "CONVERTED_UNVERIFIED")
            self.assertTrue(case["corrected_schema_validated"])
            self.assertRegex(case["corrected_assessment_sha256"], HEX64)
            self.assertRegex(case["corrected_trace_sha256"], HEX64)
        self.assertEqual(receipt["qualification"]["independent_oval_equivalence"], "not_proved")

    def test_windows_pr5_replay_is_pinned_to_current_converter(self):
        receipt = self.load("windows-policy-pr5-replay-20261119.json")
        self.assertEqual(receipt["converter"]["commit"],
                         "26fc48e13752922627c59719a53fc64db60d32ce")
        self.assertTrue(receipt["replay"]["current_replay_verified"])
        self.assertEqual(receipt["replay"]["base_diagnostics"],
                         "policy source literal must be nonnegative")
        outputs = receipt["replay"]["corrected_outputs"]
        self.assertEqual(outputs["def:705"]["assessment_sha256"],
                         receipt["cases"][0]["corrected_assessment_sha256"])
        self.assertEqual(outputs["def:998"]["assessment_sha256"],
                         receipt["cases"][1]["corrected_assessment_sha256"])
        for row in outputs.values():
            self.assertRegex(row["source_trace_sha256"], HEX64)

    def test_windows_pr10_replay_removes_deprecated_audit_field(self):
        receipt = self.load("windows-audit-deprecated-field-followup.json")
        conversion = receipt["conversion"]
        self.assertTrue(conversion["current_replay_verified"])
        self.assertEqual(conversion["baseline"]["returncode"], 1)
        self.assertEqual(conversion["candidate"]["returncode"], 0)
        self.assertRegex(conversion["candidate"]["source_trace_sha256"], HEX64)
        self.assertEqual(conversion["candidate"]["assessment_sha256"],
                         "7e2ebfa804e8d2334d429c33557f92deaa2c2ede340b5179c2911bb6b138dfe4")

    def test_windows_update_pr13_receipt_has_verified_source_identity(self):
        receipt = self.load("windows-wuaupdatesearcher-variable-followup.json")
        source = receipt["source"]
        conversion = receipt["conversion"]
        self.assertTrue(source["source_commit_blob_verified"])
        self.assertEqual(source["definition_id"], "oval:navy.navwar.niwcatlantic.scc.windows.update:def:1")
        self.assertEqual(source["variable_id"], "oval:navy.navwar.niwcatlantic.scc.windows.update:var:4")
        self.assertEqual(conversion["baseline"]["status"], "blocked")
        self.assertEqual(conversion["candidate"]["status"], "CONVERTED_UNVERIFIED")
        self.assertTrue(conversion["candidate"]["schema_validated"])
        self.assertRegex(conversion["candidate"]["assessment_sha256"], HEX64)
        self.assertRegex(source["candidate_sha256"], HEX64)
        self.assertTrue(conversion["current_replay_verified"])
        self.assertEqual(conversion["baseline"]["returncode"], 1)
        self.assertEqual(conversion["candidate"]["returncode"], 0)
        self.assertRegex(conversion["candidate"]["source_trace_sha256"], HEX64)

    def test_unix_upward_recursion_pr16_stays_deprecated(self):
        receipt = self.load("unix-upward-recursion-pr16-focused-qualification.json")
        source = receipt["source"]
        conversion = receipt["conversion"]
        self.assertEqual(source["pull_request"], 16)
        self.assertEqual(source["removed_test_id"], "oval:org.mitre.oval.test:tst:466")
        self.assertEqual(source["classification"], "deprecated_source_construct")
        self.assertTrue(source["source_commit_blob_verified"])
        self.assertEqual(conversion["base_status"], "blocked")
        self.assertEqual(conversion["corrected_status"], "CONVERTED_UNVERIFIED")
        self.assertTrue(conversion["corrected_schema_validated"])
        self.assertTrue(conversion["downward_recursion_preserved"])
        self.assertFalse(conversion["upward_recursion_enabled"])

    def test_unix_pr16_replay_keeps_upward_recursion_deprecated(self):
        receipt = self.load("unix-upward-recursion-pr16-focused-qualification.json")
        conversion = receipt["conversion"]
        self.assertTrue(conversion["current_replay_verified"])
        self.assertEqual(conversion["converter_commit"],
                         "d9addb9a9fe9699e8dea33d1bf60ecb891ccb94e")
        self.assertEqual(conversion["base_returncode"], 1)
        self.assertEqual(conversion["corrected_returncode"], 0)
        self.assertRegex(conversion["corrected_source_trace_sha256"], HEX64)
        self.assertFalse(conversion["upward_recursion_enabled"])

    def test_agnostic_external_float_pr14_preserves_input_hold(self):
        receipt = self.load("agnostic-external-float-pr14-focused-qualification.json")
        source = receipt["source"]
        conversion = receipt["conversion"]
        self.assertEqual(source["pull_request"], 14)
        self.assertEqual(source["definition_id"], "oval:org.mitre.oval.test:def:562")
        self.assertEqual(source["affected_test_id"], "oval:org.mitre.oval.test:tst:936")
        self.assertTrue(source["source_commit_blob_verified"])
        self.assertRegex(source["base_archive_sha256"], HEX64)
        self.assertRegex(source["corrected_archive_sha256"], HEX64)
        self.assertEqual(conversion["base_status"], "blocked")
        self.assertEqual(conversion["corrected_status"], "blocked")
        self.assertEqual(conversion["base_diagnostic"], conversion["corrected_diagnostic"])
        self.assertEqual(conversion["schema_validated"], False)
        self.assertIn("does not resolve", conversion["semantic_transition"])
        self.assertTrue(conversion["current_replay_verified"])
        self.assertEqual(conversion["converter_commit"],
                         "26fc48e13752922627c59719a53fc64db60d32ce")
        self.assertEqual(conversion["base_returncode"], 1)
        self.assertEqual(conversion["corrected_returncode"], 1)

    def test_macos_environmentvariable_pr6_receipt_records_type_recovery(self):
        receipt = self.load("macos-environmentvariable-pr6-focused-qualification.json")
        source = receipt["source"]
        conversion = receipt["conversion"]
        self.assertEqual(source["pull_request"], 6)
        self.assertEqual(source["definition_id"], "oval:navy.navwar.niwcatlantic.scc.test:def:1")
        self.assertEqual(source["affected_variable"], "oval:navy.navwar.niwcatlantic.scc.test:var:2")
        self.assertTrue(source["source_commit_blob_verified"])
        self.assertEqual(conversion["base_status"], "blocked")
        self.assertEqual(conversion["base_diagnostic"], "Variable cast outside bounded proof")
        self.assertEqual(conversion["corrected_status"], "CONVERTED_UNVERIFIED")
        self.assertTrue(conversion["corrected_schema_validated"])
        self.assertRegex(conversion["corrected_assessment_sha256"], HEX64)
        self.assertTrue(conversion["current_replay_verified"])
        self.assertEqual(conversion["base_returncode"], 1)
        self.assertEqual(conversion["corrected_returncode"], 0)
        self.assertRegex(conversion["corrected_source_trace_sha256"], HEX64)

    def test_password_pr18_receipt_is_replayed_at_current_head(self):
        receipt = self.load("password-pr18-focused-qualification.json")
        conversion = receipt["conversion"]
        self.assertTrue(conversion["current_replay_verified"])
        self.assertEqual(conversion["converter_commit"],
                         "d9addb9a9fe9699e8dea33d1bf60ecb891ccb94e")
        self.assertEqual(conversion["base_status"], "CONVERTED_UNVERIFIED")
        self.assertEqual(conversion["corrected_status"], "CONVERTED_UNVERIFIED")
        self.assertRegex(conversion["base_source_trace_sha256"], HEX64)
        self.assertRegex(conversion["corrected_source_trace_sha256"], HEX64)
        self.assertNotEqual(conversion["base_assessment_sha256"],
                            conversion["corrected_assessment_sha256"])

    def test_sshd_pr17_receipt_records_recovered_source_test(self):
        receipt = self.load("sshd-pr17-focused-qualification.json")
        source = receipt["source"]
        conversion = receipt["conversion"]
        self.assertEqual(source["pull_request"], 17)
        self.assertEqual(source["definition_id"], "oval:org.mitre.oval.test:def:963")
        self.assertEqual(source["affected_test_ids"], ["oval:org.mitre.oval.test:tst:483"])
        self.assertTrue(source["source_commit_blob_verified"])
        self.assertEqual(conversion["base_assessment_test_count"], 3)
        self.assertEqual(conversion["corrected_assessment_test_count"], 4)
        self.assertTrue(conversion["current_replay_verified"])
        self.assertEqual(conversion["converter_commit"],
                         "d9addb9a9fe9699e8dea33d1bf60ecb891ccb94e")
        self.assertRegex(conversion["base_source_trace_sha256"], HEX64)
        self.assertRegex(conversion["corrected_source_trace_sha256"], HEX64)
        self.assertTrue(conversion["base_schema_validated"])
        self.assertTrue(conversion["corrected_schema_validated"])
        self.assertRegex(conversion["corrected_assessment_sha256"], HEX64)
        self.assertEqual(conversion["independent_runtime_equivalence"], "not_proved")

    def test_windows_pr9_replay_keeps_object_note_semantics_equal(self):
        receipt = self.load("windows-object-notes-followup.json")
        conversion = receipt["conversion"]
        self.assertTrue(conversion["current_replay_verified"])
        self.assertEqual(conversion["baseline"]["status"], "CONVERTED_UNVERIFIED")
        self.assertEqual(conversion["candidate"]["status"], "CONVERTED_UNVERIFIED")
        self.assertTrue(conversion["assessment_semantics_equal"])
        self.assertRegex(conversion["base_source_trace_sha256"], HEX64)
        self.assertRegex(conversion["candidate"]["source_trace_sha256"], HEX64)
        self.assertEqual(conversion["candidate"]["assessment_sha256"],
                         "c84d3f9e82dc4efdeff8d67d7b6208524253658ae39e8d0547175dbc471f10a1")

    def test_windows_policy_pr5_receipt_distinguishes_source_hold_and_recovery(self):
        receipt = self.load("windows-policy-pr5-focused-qualification.json")
        source = receipt["source"]
        conversion = receipt["conversion"]
        self.assertEqual(source["pull_request"], 5)
        self.assertEqual(source["classification"], "source_typed_literal_invalid")
        self.assertTrue(source["source_commit_blob_verified"])
        self.assertIn("0", source["files"][1]["correction"])
        self.assertEqual(source["files"][1]["correction"].split(";")[0], "max_passwd_age -1 -> 0")
        self.assertIn("broad schema-valid lower bound 0", source["interpretation"])
        self.assertEqual(len(source["files"]), 2)
        self.assertEqual(len(conversion["cases"]), 2)
        for case in conversion["cases"]:
            self.assertEqual(case["base_status"], "blocked")
            self.assertEqual(case["corrected_status"], "CONVERTED_UNVERIFIED")
            self.assertTrue(case["corrected_schema_validated"])
            self.assertRegex(case["corrected_assessment_sha256"], HEX64)
        self.assertEqual(conversion["independent_runtime_equivalence"], "not_proved")

    def test_full_parity_receipt_retains_source_invalid_variable_evidence(self):
        receipt = self.load("converter-full-parity-20261119.json")
        audit = receipt["audit"]
        self.assertEqual(audit["commit"], "33c1c08")
        self.assertEqual(audit["source_invalid_definition_count"], 8)
        self.assertEqual(audit["problem_types"].get("source_invalid"), 8)
        rows = audit["source_invalid_rows"]
        self.assertEqual(len(rows), 8)
        definitions = {row["definition_id"] for row in rows}
        self.assertIn("oval:org.mitre.oval.test:def:580", definitions)
        self.assertIn("oval:navy.navwar.niwcatlantic.scc:def:38", definitions)
        for row in rows:
            self.assertRegex(row["source_xml_sha256"], HEX64)
            self.assertTrue(row["affected_test_ids"])
            self.assertEqual(row["disposition"], "source_invalid_non_equivalence")
            for variable in row["variables"]:
                self.assertRegex(variable["source_variable_xml_sha256"], HEX64)
                self.assertIn("declared_datatype", variable)

    def test_committed_receipt_is_compact_and_does_not_embed_source_or_host_data(self):
        path = ROOT / "docs" / "evidence" / "issue83" / "nvram-pr19-focused-qualification.json"
        receipt = self.load("nvram-pr19-focused-qualification.json")
        self.assertLess(path.stat().st_size, 16 * 1024)
        self.assertEqual(receipt["reproduction"]["evidence_root"], "<fresh-external-temp-directory>")
        self.assertEqual(receipt["reproduction"]["generated_evidence_commit"], "not committed; compact hashes only")
        self.assertNotIn("<nvram512_object", path.read_text(encoding="utf-8"))
        self.assertIn("0a1ee9365aff7962118f316ed9df822217bbf850", receipt["reproduction"]["source_fetch"])


if __name__ == "__main__":
    unittest.main()
