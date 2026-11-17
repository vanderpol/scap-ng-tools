"""Regression tests for approved source-only OVAL 0.4.1 typing compatibility."""
import unittest
from xml.etree import ElementTree as ET

from scap_ng_tools.converter.native041_self_assertion_typing import (
    PINNED, SOURCE_COMMIT, prepare_nodes, qualification_policy, trace_records,
)
from scap_ng_tools.converter.oval_platform import StandalonePlatformSource

PREFIX = "http://oval.mitre.org/XMLSchema/oval-definitions-5"


def variable_element(identifier, datatype, value):
    kind = "local_variable" if identifier.endswith("var:1") else "constant_variable"
    return ET.fromstring(
        f'<{kind} id="{identifier}" datatype="{datatype}"><value>{value}</value></{kind}>'
    )


class PinnedSelfAssertionTypingTests(unittest.TestCase):
    def test_exact_source_and_commit_are_required(self):
        self.assertEqual(len(PINNED), 3)
        self.assertEqual(sum(map(len, PINNED.values())), 8)
        for (path, source_sha), correction in PINNED.items():
            self.assertEqual(
                qualification_policy(source_commit=SOURCE_COMMIT,
                                     source_path=path, source_sha256=source_sha),
                correction,
            )
            self.assertEqual(qualification_policy(source_commit="0" * 40,
                                                  source_path=path,
                                                  source_sha256=source_sha), {})
            self.assertEqual(
                qualification_policy(source_commit=SOURCE_COMMIT,
                                     source_path="SCAP_1.4/OVAL_Test_Content/" + path,
                                     source_sha256=source_sha),
                correction,
            )
            self.assertEqual(qualification_policy(source_commit=SOURCE_COMMIT,
                                                  source_path=path,
                                                  source_sha256="0" * 64), {})
            self.assertEqual(qualification_policy(source_commit=SOURCE_COMMIT,
                                                  source_path="agnostic/unrelated.xml",
                                                  source_sha256=source_sha), {})

    def test_normalization_uses_clones_without_touching_original(self):
        path = "agnostic/oval-def_criterion.xml"
        src_sha = next(d for p, d in PINNED if p == path)
        correction = qualification_policy(source_commit=SOURCE_COMMIT,
                                          source_path=path, source_sha256=src_sha)
        nodes = {
            key: variable_element(key, declared, "true")
            for key, (declared, _) in correction.items()
        }
        before = {key: ET.tostring(node) for key, node in nodes.items()}
        clones = prepare_nodes(nodes, correction, source_path=path)
        self.assertEqual(set(clones), set(correction))
        for key, (_, expected) in correction.items():
            self.assertIsNot(clones[key], nodes[key])
            self.assertEqual(clones[key].get("datatype"), expected)
            self.assertEqual(ET.tostring(nodes[key]), before[key])
        receipts = trace_records(nodes, clones, correction)
        self.assertEqual(len(receipts), 2)
        self.assertEqual({r["declared_datatype"] for r in receipts}, {"binary"})
        self.assertEqual({r["native_result_datatype"] for r in receipts}, {"boolean"})
        self.assertTrue(all(r["original_node_sha256"] !=
                            r["normalized_visitor_node_sha256"] for r in receipts))

    def test_declaration_mismatch_rejects_entire_overlay(self):
        corrections = {"variable-one": ("binary", "boolean")}
        nodes = {"variable-one": variable_element("variable-one", "int", "true")}
        with self.assertRaisesRegex(ValueError, "expected original datatype"):
            prepare_nodes(nodes, corrections, source_path="fixture.xml")
        with self.assertRaisesRegex(ValueError, "approved source Variable missing"):
            prepare_nodes({}, corrections, source_path="fixture.xml")

    def test_original_source_index_is_never_mutated(self):
        raw = (f'<oval_definitions xmlns="{PREFIX}"><generator>'
               f'<schema_version xmlns="http://oval.mitre.org/XMLSchema/oval-common-5">5.12.3</schema_version>'
               f'</generator><variables><constant_variable id="test-variable" datatype="binary">'
               f'<value>true</value></constant_variable></variables></oval_definitions>').encode()
        source = StandalonePlatformSource(raw, "agnostic/test.xml")
        source._qualified_typing_nodes = prepare_nodes(
            source.node_index, {"test-variable": ("binary", "boolean")},
            source_path="agnostic/test.xml",
        )
        converted = source.node("agnostic/test.xml", "test-variable", "variable")
        original = source.node_index["test-variable"]
        self.assertEqual(converted.get("datatype"), "boolean")
        self.assertEqual(original.get("datatype"), "binary")
        self.assertIsNot(converted, original)

    def test_integer_variable_100_remains_integer(self):
        path = "agnostic/oval-def_merge.xml"
        src_sha = next(d for p, d in PINNED if p == path)
        policy = qualification_policy(source_commit=SOURCE_COMMIT,
                                      source_path=path, source_sha256=src_sha)
        self.assertNotIn("oval:navy.navwar.niwcatlantic.scc:var:100", policy)
        self.assertEqual(len(policy), 5)


if __name__ == "__main__":
    unittest.main()
