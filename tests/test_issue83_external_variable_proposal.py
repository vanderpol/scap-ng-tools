"""Review-only acceptance vectors for the proposed external Input contract.

These tests deliberately do not modify or exercise the production converter.
They make the pending canonical decision executable: branch OR semantics,
typed/cardinality validation, all Boolean operators, optional guards, and
no-default behavior must be agreed before schema/converter/RI implementation.
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
        self.assertEqual(len(vectors), 24)
        for name in ("and", "or", "one", "xor"):
            self.assertTrue(any(name in v.get("constraints", {}).get("predicate", {})
                                for v in vectors.values()))
        self.assertIn("schema_reject", {v["expected"] for v in vectors.values()})
        self.assertIn("not_evaluated", {v["expected"] for v in vectors.values()})
        self.assertEqual(self.proposal["vector_policy"]["max_boolean_branch_count"], 64)

    def test_candidate_branch_and_binding_semantics(self):
        for vector in self.proposal["vectors"]:
            with self.subTest(vector=vector["id"]):
                self.assertEqual(self._evaluate(vector), vector["expected"])

    @classmethod
    def _evaluate(cls, vector):
        expected = vector["expected"]
        if expected == "schema_reject":
            return expected
        supplied = vector.get("supplied")
        if supplied is None:
            if vector.get("required"):
                return "not_evaluated"
            return "not_evaluated" if vector.get("consumer_guard") else "error"
        count = len(supplied)
        bounds = {"exactly_one": count == 1, "zero_or_one": count <= 1,
                  "one_or_more": count >= 1, "zero_or_more": True}
        if not bounds[vector["cardinality"]]:
            return "error"
        datatype = vector["datatype"]
        if datatype == "integer" and any(type(value) is not int for value in supplied):
            return "error"
        if datatype == "string" and any(type(value) is not str for value in supplied):
            return "error"
        constraints = vector.get("constraints", {})
        for value in supplied:
            alternatives = []
            alternatives.extend(value == allowed for allowed in constraints.get("allowed", []))
            if "predicate" in constraints:
                alternatives.append(cls._expression(constraints["predicate"], value))
            if alternatives and not any(alternatives):
                return "error"
        return "accepted"

    @classmethod
    def _expression(cls, expression, value):
        if "and" in expression:
            return all(cls._expression(child, value) for child in expression["and"])
        if "or" in expression:
            return any(cls._expression(child, value) for child in expression["or"])
        if "one" in expression:
            return sum(cls._expression(child, value) for child in expression["one"]) == 1
        if "xor" in expression:
            return sum(cls._expression(child, value) for child in expression["xor"]) % 2 == 1
        if "matches_regex" in expression:
            pattern = expression["matches_regex"]
            return bool(re.fullmatch(pattern, value))
        if "equals" in expression:
            return value == expression["equals"]
        if "greater_than_or_equal" in expression:
            return value >= expression["greater_than_or_equal"]
        if "less_than_or_equal" in expression:
            return value <= expression["less_than_or_equal"]
        raise AssertionError("unmodeled proposal expression")


if __name__ == "__main__":
    unittest.main()
