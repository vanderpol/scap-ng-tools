import unittest

from scripts.reconcile_cross_branch_evidence import reconcile_documents


class CrossBranchEvidenceTests(unittest.TestCase):
    def _row(self, branch, counts, fmt, blocked, dynamic=(), to_integer=True,
             source_repo="niwc-atlantic/scap-content-library"):
        return {
            "branch": branch,
            "ref": "origin/" + branch,
            "path": "receipt.json",
            "receipt_sha256": branch * 64,
            "format": fmt,
            "source": {"repository": source_repo, "commit": "source", "archive_sha256": "archive"},
            "canonical": {"commit": "canonical", "flat_schema_sha256": "flat-" + branch},
            "converter_commit": "converter-" + branch,
            "counts": counts,
            "categories": {},
            "blocked_rule_count": blocked,
            "blocked_rule_ids_sha256": "ids-" + branch,
            "dynamic_variable_object_set_rule_ids": list(dynamic),
            "to_integer_blocked": to_integer,
            "remaining_canonical_gaps": {},
            "proof_boundary": "structural only",
        }

    def test_newer_disposition_receipt_wins_and_old_branch_is_stale(self):
        old = self._row("main", {"converted": 6492, "blocked": 95, "manual_only": 1403},
                        "full65-current-449", 95, to_integer=True)
        new = self._row("pr99", {"converted": 6493, "blocked": 94, "manual_only": 1403},
                        "full65-blocker-disposition/2", 94,
                        dynamic=("rule-a", "rule-b"), to_integer=False)
        result = reconcile_documents([old, new])
        self.assertEqual(result["authoritative_branch"], "pr99")
        self.assertTrue(result["source_identity_agrees"])
        self.assertEqual(result["authoritative_counts"]["blocked"], 94)
        self.assertEqual(result["authoritative_dynamic_variable_object_set_rule_ids"], ["rule-a", "rule-b"])
        self.assertFalse(result["authoritative_to_integer_blocked"])
        self.assertEqual(result["stale_or_incomplete_branches"], ["main"])

    def test_source_repository_default_is_not_a_false_disagreement(self):
        left = self._row("left", {"converted": 1, "blocked": 0, "manual_only": 0}, "x", 0,
                         source_repo="niwc-atlantic/scap-content-library")
        right = self._row("right", {"converted": 1, "blocked": 0, "manual_only": 0}, "x", 0,
                          source_repo="niwc-atlantic/scap-content-library")
        result = reconcile_documents([left, right])
        self.assertTrue(result["source_identity_agrees"])


if __name__ == "__main__":
    unittest.main()
