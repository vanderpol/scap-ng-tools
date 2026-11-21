"""Review-only acceptance vectors for the proposed external Input contract.

These tests deliberately do not modify or exercise the production converter.
They make the pending canonical decision executable: branch OR semantics,
typed/cardinality validation, and no-default behavior must be agreed before
schema/converter/RI implementation begins.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROPOSAL = ROOT / "docs/evidence/issue83/external-variable-restriction-proposal.json"


class ProposedExternalVariableContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proposal = json.loads(PROPOSAL.read_text(encoding="utf-8"))

    def test_is_review_only_and_source_pinned(self):
        self.assertEqual(self.proposal["status"], "proposal_only")
        source = self.proposal["source"]
        self.assertEqual(source["definition_id"], "oval:org.mitre.oval.test:def:562")
        self.assertEqual(
            source["definition_member_sha256"],
            "df3a7bfbcf54b48652ed5c5ece93131c4c82ac2f07ff4056f5ed4668160dc8c1",
        )
        self.assertEqual(
            self.proposal["canonical_baseline"]["flat_schema_sha256"],
            "11b5ae735dd0a7a1db496b421e0d12f757c027f734da688c2b1d96940f4c47dc",
        )

    def test_vectors_cover_required_semantic_boundaries(self):
        vectors = {vector["id"]: vector for vector in self.proposal["vectors"]}
        expected = {
            "allowed-single-positive", "allowed-single-negative",
            "restriction-single-positive", "restriction-single-negative",
            "restriction-or-first", "restriction-or-second",
            "restriction-or-negative", "typed-numeric-positive",
            "typed-numeric-negative", "wrong-datatype", "missing-required",
            "optional-unbound-guarded", "optional-unbound-unguarded",
            "empty-exactly-one", "empty-zero-or-more",
            "multi-value-one-or-more", "multi-value-exactly-one",
        }
        self.assertEqual(set(vectors), expected)
        self.assertEqual(
            {vector["expected"] for vector in vectors.values()},
            {"accepted", "error", "not_evaluated"},
        )

    def test_candidate_branch_and_binding_semantics(self):
        for vector in self.proposal["vectors"]:
            with self.subTest(vector=vector["id"]):
                self.assertEqual(self._evaluate(vector), vector["expected"])

    @staticmethod
    def _evaluate(vector):
        supplied = vector.get("supplied")
        if supplied is None:
            if vector.get("required"):
                return "not_evaluated"
            return "not_evaluated"  # consumer guard is required either way

        cardinality = vector["cardinality"]
        count = len(supplied)
        bounds = {
            "exactly_one": count == 1,
            "zero_or_one": count <= 1,
            "one_or_more": count >= 1,
            "zero_or_more": True,
        }
        if not bounds[cardinality]:
            return "error"

        datatype = vector["datatype"]
        if datatype == "integer" and any(type(value) is not int for value in supplied):
            return "error"
        if datatype == "string" and any(type(value) is not str for value in supplied):
            return "error"

        constraints = vector.get("constraints", {})
        for value in supplied:
            branches = [{"kind": "allowed", "value": allowed}
                        for allowed in constraints.get("allowed", [])]
            branches.extend({"kind": "restriction", **group}
                            for group in constraints.get("restriction_groups", []))
            if not branches:
                continue
            valid = False
            for branch in branches:
                if branch["kind"] == "allowed":
                    valid |= value == branch["value"]
                    continue
                outcomes = []
                for predicate in branch["predicates"]:
                    operation = predicate["operation"]
                    bound = predicate["value"]
                    if operation == "pattern_match":
                        outcomes.append(bool(re.fullmatch(bound, value)))
                    elif operation == "greater_than_or_equal":
                        outcomes.append(value >= bound)
                    else:
                        raise AssertionError("unmodeled proposal operation")
                valid |= all(outcomes) if branch["operator"] == "and" else any(outcomes)
            if not valid:
                return "error"
        return "accepted"


if __name__ == "__main__":
    unittest.main()
