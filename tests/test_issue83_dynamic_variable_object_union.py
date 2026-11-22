"""Generic lowering tests for dynamic OVAL Variable Object UNION populations.

These tests exercise the production visitor's lowering boundary.  They do not
claim Windows collector or RI runtime equivalence: source-backed IIS cases
remain subject to their complete OVAL closure and Schematron validity.
"""
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

from scap_ng_tools.converter.direct04 import load_runtime

load_runtime()
from v04_direct_converter import AssessmentConverter  # noqa: E402
from v04_direct_scap_source import OVAL  # noqa: E402


def oval(source):
    return ET.fromstring(source.replace(
        'xmlns="OVAL#independent"', f'xmlns="{OVAL}#independent"'
    ).replace('xmlns="OVAL"', f'xmlns="{OVAL}"'))


class DynamicVariableObjectUnion(unittest.TestCase):
    def visitor(self, nodes, references):
        class Source:
            native_recovery = True

            def node(self, _component, identifier, _kind):
                return nodes[identifier]

        visitor = AssessmentConverter(Source(), "component", [], native_recovery=True)
        visitor.reference = lambda identifier, _kind: references[identifier]
        visitor.native_name = lambda element, _kind, title=None: element.get("id") + "-variable"
        return visitor

    def test_production_visitor_lowers_runtime_union_to_unique_expression(self):
        nodes = {
            "root": oval(
                '<variable_object xmlns="OVAL" id="root"><set set_operator="UNION">'
                '<object_reference>left</object_reference><object_reference>right</object_reference>'
                '</set></variable_object>'
            ),
            "left": oval('<variable_object xmlns="OVAL" id="left"><var_ref>one</var_ref></variable_object>'),
            "right": oval('<variable_object xmlns="OVAL" id="right"><var_ref>two</var_ref></variable_object>'),
            "one": oval('<local_variable xmlns="OVAL" id="one" datatype="string"><literal_component>one</literal_component></local_variable>'),
            "two": oval('<local_variable xmlns="OVAL" id="two" datatype="string"><literal_component>two</literal_component></local_variable>'),
        }
        references = {
            "one": {"variable": "one-variable"},
            "two": {"variable": "two-variable"},
        }
        visitor = self.visitor(nodes, references)
        self.assertTrue(visitor._dynamic_variable_union_candidate(nodes["root"]))
        result = visitor.dynamic_variable_object_set(nodes["root"])
        self.assertEqual(result, {"variable": "root-variable"})
        self.assertEqual(visitor.variables["root-variable"], {
            "kind": "local",
            "expression": {"unique": [
                {"variable": "one-variable"},
                {"variable": "two-variable"},
            ]},
        })
        warning = visitor.conversion_warnings[0]
        self.assertEqual(warning["code"], "oval_dynamic_variable_object_union_lowered")
        self.assertEqual(warning["source_set_operator"], "UNION")
        self.assertFalse(warning["scanner_evaluated"])

    def test_typed_variable_reference_operands_keep_one_derived_datatype(self):
        """Named typed Variables remain runtime operands, not source literals."""
        nodes = {
            "root": oval(
                '<variable_object xmlns="OVAL" id="root"><set set_operator="UNION">'
                '<object_reference>left</object_reference><object_reference>right</object_reference>'
                '</set></variable_object>'
            ),
            "left": oval('<variable_object xmlns="OVAL" id="left"><var_ref>one</var_ref></variable_object>'),
            "right": oval('<variable_object xmlns="OVAL" id="right"><var_ref>two</var_ref></variable_object>'),
            "one": oval('<local_variable xmlns="OVAL" id="one" datatype="int"><literal_component datatype="int">7</literal_component></local_variable>'),
            "two": oval('<local_variable xmlns="OVAL" id="two" datatype="int"><literal_component datatype="int">9</literal_component></local_variable>'),
        }
        references = {
            "one": {"variable": "one-variable"},
            "two": {"variable": "two-variable"},
        }
        visitor = self.visitor(nodes, references)
        result = visitor.dynamic_variable_object_set(nodes["root"])
        self.assertEqual(visitor.variables[result["variable"]]["expression"], {
            "unique": [
                {"variable": "one-variable"},
                {"variable": "two-variable"},
            ],
        })
        self.assertEqual(visitor.conversion_warnings[0]["source_variable_datatypes"], ["int"])

        # This is the shared type gate, not value execution.  It proves that
        # the same native expression derives one scalar datatype when the
        # named operands are typed Variables.
        from scap_ng_tools.converter._v04_semantic import v04_variable_expressions as semantic
        class CandidateSchema:
            def iter_errors(self, declaration):
                return iter(())
        assessment = {"variables": {
            "one-variable": {"kind": "local", "expression": {
                "literal": {"datatype": "integer", "value": 7}}},
            "two-variable": {"kind": "local", "expression": {
                "literal": {"datatype": "integer", "value": 9}}},
            "union-variable": {"kind": "local", "expression": {
                "unique": [{"variable": "one-variable"},
                            {"variable": "two-variable"}]}},
        }}
        with patch.object(semantic, "declaration_validator", return_value=CandidateSchema()):
            derived = semantic.assessment_variable_expressions(assessment)
        self.assertEqual(derived["union-variable"], "integer")

    def test_duplicate_operands_preserve_source_order_for_runtime_unique(self):
        """Conversion preserves operand order; native unique owns deduplication."""
        nodes = {
            "root": oval(
                '<variable_object xmlns="OVAL" id="root"><set set_operator="UNION">'
                '<object_reference>left</object_reference><object_reference>right</object_reference>'
                '<object_reference>left</object_reference></set></variable_object>'
            ),
            "left": oval('<variable_object xmlns="OVAL" id="left"><var_ref>one</var_ref></variable_object>'),
            "right": oval('<variable_object xmlns="OVAL" id="right"><var_ref>two</var_ref></variable_object>'),
            "one": oval('<local_variable xmlns="OVAL" id="one" datatype="string"><literal_component>left</literal_component></local_variable>'),
            "two": oval('<local_variable xmlns="OVAL" id="two" datatype="string"><literal_component>right</literal_component></local_variable>'),
        }
        visitor = self.visitor(nodes, {
            "one": {"variable": "one-variable"},
            "two": {"variable": "two-variable"},
        })
        result = visitor.dynamic_variable_object_set(nodes["root"])
        self.assertEqual(visitor.variables[result["variable"]]["expression"], {
            "unique": [
                {"variable": "one-variable"},
                {"variable": "two-variable"},
                {"variable": "one-variable"},
            ],
        })
        self.assertEqual(visitor.conversion_warnings[0]["source_variable_ids"],
                         ["one", "two"])

    def test_empty_and_multivalue_operands_remain_runtime_references(self):
        """Empty/multivalue populations are not collapsed during conversion."""
        nodes = {
            "root": oval(
                '<variable_object xmlns="OVAL" id="root"><set set_operator="UNION">'
                '<object_reference>empty</object_reference><object_reference>many</object_reference>'
                '</set></variable_object>'
            ),
            "empty": oval('<variable_object xmlns="OVAL" id="empty"><var_ref>empty-source</var_ref></variable_object>'),
            "many": oval('<variable_object xmlns="OVAL" id="many"><var_ref>many-source</var_ref></variable_object>'),
            "empty-source": oval('<local_variable xmlns="OVAL" id="empty-source" datatype="string"><literal_component>unused</literal_component></local_variable>'),
            "many-source": oval('<local_variable xmlns="OVAL" id="many-source" datatype="string"><literal_component>unused</literal_component></local_variable>'),
        }
        visitor = self.visitor(nodes, {
            "empty-source": {"variable": "empty-source-variable"},
            "many-source": {"variable": "many-source-variable"},
        })
        result = visitor.dynamic_variable_object_set(nodes["root"])
        expression = visitor.variables[result["variable"]]["expression"]
        self.assertEqual(expression, {"unique": [
            {"variable": "empty-source-variable"},
            {"variable": "many-source-variable"},
        ]})
        self.assertNotIn("literal", str(expression))
        self.assertFalse(visitor.conversion_warnings[0]["scanner_evaluated"])

        # Typed empty and multivalue domains remain one scalar type at the
        # semantic boundary; their actual cardinality is a runtime concern.
        from scap_ng_tools.converter._v04_semantic import v04_variable_expressions as semantic
        class CandidateSchema:
            def iter_errors(self, declaration):
                return iter(())
        assessment = {"variables": {
            "empty-variable": {"kind": "local", "expression": {
                "literal": {"datatype": "string", "value": []}}},
            "many-variable": {"kind": "local", "expression": {
                "literal": {"datatype": "string", "value": ["a", "b", "a"]}}},
            "population-variable": {"kind": "local", "expression": {
                "unique": [{"variable": "empty-variable"},
                            {"variable": "many-variable"}]}},
        }}
        with patch.object(semantic, "declaration_validator", return_value=CandidateSchema()):
            derived = semantic.assessment_variable_expressions(assessment)
        self.assertEqual(derived["population-variable"], "string")

    def test_none_satisfy_remains_a_value_quantifier_not_a_boolean_group(self):
        nodes = {
            "root": oval(
                '<variable_object xmlns="OVAL#independent" id="root"><set xmlns="OVAL" set_operator="UNION">'
                '<object_reference>left</object_reference><object_reference>right</object_reference>'
                '</set></variable_object>'
            ),
            "left": oval('<variable_object xmlns="OVAL#independent" id="left"><var_ref>one</var_ref></variable_object>'),
            "right": oval('<variable_object xmlns="OVAL#independent" id="right"><var_ref>two</var_ref></variable_object>'),
            "one": oval('<local_variable xmlns="OVAL" id="one" datatype="string"><literal_component>safe</literal_component></local_variable>'),
            "two": oval('<local_variable xmlns="OVAL" id="two" datatype="string"><literal_component>safe</literal_component></local_variable>'),
            "state": oval('<variable_state xmlns="OVAL#independent" id="state"><value operation="equals">bad</value></variable_state>'),
        }

        class Source:
            native_recovery = True
            standalone_oval = True
            preserve_source_variables = True

            def node(self, _component, identifier, _kind):
                return nodes[identifier]

            def object_uses(self, _component, _identifier, _kind):
                return {"root": 1, "left": 1, "right": 1}

        mapping = {
            "capability": "variable.value",
            "source": {
                "namespace": OVAL + "#independent",
                "test": "variable_test",
                "object": "variable_object",
                "state": "variable_state",
            },
            "native": {
                "test_source": {"kind": "variable"},
                "state_field_map": {"value": "value"},
                "field_datatypes": {"value": ["string"]},
            },
        }
        visitor = AssessmentConverter(Source(), "component", [mapping], native_recovery=True)
        result = visitor.convert_test(oval(
            '<variable_test xmlns="OVAL#independent" id="test" check="none satisfy" '
            'check_existence="at_least_one_exists"><object object_ref="root"/>'
            '<state state_ref="state"/></variable_test>'))
        self.assertEqual(result, {"test": "variable-test-test"})
        native = visitor.tests["variable-test-test"]
        self.assertEqual(native["require"]["field_requirement"]["values_matching"], "none")
        self.assertEqual(native["require"]["fields"]["value"]["equals"], "bad")
        self.assertIn("variable", native)

    def test_static_and_dynamic_operands_keep_named_variable_identity(self):
        nodes = {
            "root": oval(
                '<variable_object xmlns="OVAL" id="root"><set set_operator="UNION">'
                '<object_reference>left</object_reference><object_reference>right</object_reference>'
                '</set></variable_object>'
            ),
            "left": oval('<variable_object xmlns="OVAL" id="left"><var_ref>one</var_ref></variable_object>'),
            "right": oval('<variable_object xmlns="OVAL" id="right"><var_ref>two</var_ref></variable_object>'),
            "one": oval('<constant_variable xmlns="OVAL" id="one" datatype="string"><value>static</value></constant_variable>'),
            "two": oval('<local_variable xmlns="OVAL" id="two" datatype="string"><literal_component>dynamic</literal_component></local_variable>'),
        }
        references = {"one": ["static"], "two": {"variable": "dynamic-variable"}}
        visitor = self.visitor(nodes, references)
        # The converter must not inline the static value or turn a dynamic
        # source into a host-time literal when a mixed UNION is encountered.
        visitor.named_variable = lambda identifier: identifier + "-named"
        result = visitor.dynamic_variable_object_set(nodes["root"])
        self.assertEqual(result, {"variable": "root-variable"})
        self.assertEqual(visitor.variables["root-variable"]["expression"], {
            "unique": [
                {"variable": "one-named"},
                {"variable": "dynamic-variable"},
            ]
        })

    def test_non_union_and_variable_object_filter_remain_fail_closed(self):
        nodes = {
            "intersection": oval(
                '<variable_object xmlns="OVAL" id="intersection"><set set_operator="INTERSECTION">'
                '<object_reference>left</object_reference><object_reference>right</object_reference>'
                '</set></variable_object>'
            ),
            "filtered": oval(
                '<variable_object xmlns="OVAL" id="filtered"><set set_operator="UNION">'
                '<object_reference>left</object_reference><filter action="include">state</filter>'
                '</set></variable_object>'
            ),
            "left": oval('<variable_object xmlns="OVAL" id="left"><var_ref>one</var_ref></variable_object>'),
            "right": oval('<variable_object xmlns="OVAL" id="right"><var_ref>two</var_ref></variable_object>'),
            "one": oval('<local_variable xmlns="OVAL" id="one" datatype="string"><literal_component>one</literal_component></local_variable>'),
            "two": oval('<local_variable xmlns="OVAL" id="two" datatype="string"><literal_component>two</literal_component></local_variable>'),
        }
        visitor = self.visitor(nodes, {"one": {"variable": "one-variable"}, "two": {"variable": "two-variable"}})
        self.assertFalse(visitor._dynamic_variable_union_candidate(nodes["intersection"]))
        self.assertFalse(visitor._dynamic_variable_union_candidate(nodes["filtered"]))
        with self.assertRaisesRegex(ValueError, "dynamic or filtered Variable Object Set"):
            visitor.static_variable_object(nodes["filtered"])

    def test_cycle_mutation_is_rejected_before_native_expression(self):
        nodes = {
            "root": oval(
                '<variable_object xmlns="OVAL" id="root"><set set_operator="UNION">'
                '<object_reference>root</object_reference></set></variable_object>'
            )
        }
        visitor = self.visitor(nodes, {})
        self.assertFalse(visitor._dynamic_variable_union_candidate(nodes["root"]))
        with self.assertRaisesRegex(ValueError, "cyclic static Variable Object Set"):
            visitor.static_variable_object(nodes["root"])

class DynamicVariableObjectReceipt(unittest.TestCase):
    def test_source_receipt_preserves_both_cases_and_schematron_findings(self):
        import json
        from pathlib import Path
        receipt = json.loads((Path(__file__).parents[1] / "docs/evidence/issue83/dynamic-variable-object-set-receipt.json").read_text())
        self.assertEqual(receipt["source_commit"], "8c8e5dff860af6b1290ee9273a282db24278f8d5")
        self.assertEqual(receipt["oval_schema_commit"], "2f140ee5c5dd1ed9606fcd5afc301f6baeb48706")
        self.assertEqual(receipt["canonical_schema_commit"],
                         "f51ab2c5bd82c94a9c292a7abb2ef1a7edc91ca2")
        self.assertEqual(receipt["canonical"]["schema_commit"],
                         "f51ab2c5bd82c94a9c292a7abb2ef1a7edc91ca2")
        self.assertEqual(receipt["canonical"]["schema_family_sha256"],
                         "11b5ae735dd0a7a1db496b421e0d12f757c027f734da688c2b1d96940f4c47dc")
        self.assertEqual(receipt["converter_schema_pin"], {
            "commit": "f51ab2c5bd82c94a9c292a7abb2ef1a7edc91ca2",
            "schema_family_sha256": "11b5ae735dd0a7a1db496b421e0d12f757c027f734da688c2b1d96940f4c47dc",
        })
        self.assertEqual(receipt["canonical_repository_head"],
                         "f51ab2c5bd82c94a9c292a7abb2ef1a7edc91ca2")
        self.assertEqual(receipt["production_replay"]["schema_commit"],
                         "f51ab2c5bd82c94a9c292a7abb2ef1a7edc91ca2")
        self.assertEqual(receipt["production_replay"]["schema_family_sha256"],
                         "11b5ae735dd0a7a1db496b421e0d12f757c027f734da688c2b1d96940f4c47dc")
        self.assertFalse(receipt["canonical"]["active_foreach_authoring"])
        self.assertEqual(len(receipt["cases"]), 2)
        for case in receipt["cases"]:
            self.assertTrue(case["schematron"]["cross_capability_filter_findings"])
            self.assertEqual(case["attempts"]["unique_expression"]["status"], "candidate_generic_lowering")
            self.assertEqual(case["source"]["xml_member_sha256"].__len__(), 64)
            self.assertNotIn("values", json.dumps(case["graph"]))
        self.assertEqual(receipt["generic_witnesses"]["status_error_boundary"]["proof"],
                         "not_run_runtime_preserved_as_explicit_hold")
        self.assertEqual(receipt["conclusion"]["original_source_disposition"],
                         "source_schematron_hold_pending_upstream_correction_or_explicit_reclassification")

    def test_lowered_expression_is_admitted_by_pinned_native_schema(self):
        import json
        import os
        from pathlib import Path
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
        root = os.environ.get("SCAP_NG_SCHEMA_ROOT")
        if not root:
            self.skipTest("set SCAP_NG_SCHEMA_ROOT to the exact canonical 0.4.1 schema")
        schema_root = Path(root)
        if (schema_root / "schema").is_dir():
            schema_root = schema_root / "schema"
        variable_path = schema_root / "variable-expression.schema.json"
        if not variable_path.is_file():
            self.skipTest("canonical variable-expression schema is unavailable")
        resources = {}
        for path in schema_root.glob("*.json"):
            document = json.loads(path.read_text(encoding="utf-8"))
            if "$schema" not in document:
                continue
            resource = Resource.from_contents(document)
            resources[f"https://scap-ng.dev/schema/v0.4.1/{path.name}"] = resource
            if document.get("$id"):
                resources[document["$id"]] = resource
        registry = Registry().with_resources(resources.items())
        schema = json.loads(variable_path.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema, registry=registry)
        instances = [{"kind": "local", "expression": {"unique": [
            {"variable": "translated-paths-variable"},
            {"values": {"object": {"object_ref": "direct-paths-object"}, "field": "result"}},
        ]}}, {
            "kind": "local", "expression": {"unique": {
                "values": {"object": {"object_ref": "typed-file-object"}, "field": "size"}
            }}
        }, {
            "kind": "local", "expression": {"unique": [{
                "literal": {"datatype": "string", "value": ["b", "a", "b"]}
            }, {"variable": "ordered-variable"}]}
        }]
        for instance in instances:
            with self.subTest(instance=instance):
                self.assertEqual(list(validator.iter_errors(instance)), [])

    def test_singleton_typed_collected_field_derives_item_datatype(self):
        """A singleton values projection uses the mapped Item field type."""
        import os
        from pathlib import Path
        from scap_ng_tools.contracts.schema_snapshot_v041 import Pinned041SchemaSnapshot
        from scap_ng_tools.converter._v04_semantic import selected_schema
        from scap_ng_tools.converter._v04_semantic import v04_variable_expressions as semantic
        root = os.environ.get("SCAP_NG_SCHEMA_ROOT")
        if not root:
            self.skipTest("set SCAP_NG_SCHEMA_ROOT to the exact canonical 0.4.1 schema")
        snapshot = Pinned041SchemaSnapshot(Path(root))
        assessment = {"variables": {
            "file-size-variable": {"kind": "local", "expression": {
                "unique": {"values": {
                    "object": {"capability": "unix.file",
                                "filepath": {"equals": "/tmp/typed-file"}},
                    "field": "size",
                }},
            }},
        }}
        with selected_schema(snapshot):
            derived = semantic.assessment_variable_expressions(assessment)
        self.assertEqual(derived["file-size-variable"], "integer")
