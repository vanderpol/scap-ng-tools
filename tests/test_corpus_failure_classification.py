"""The full-corpus ledger preserves precise source-hold classifications."""
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    'convert_self_assertion_corpus', ROOT / 'scripts/convert_self_assertion_corpus.py')
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(_MODULE)


class CorpusFailureClassificationTests(unittest.TestCase):
    def test_deprecated_wins_over_unsupported(self):
        self.assertEqual(
            _MODULE.classify_failure('', 'deprecated source capability: package511_test'),
            'deprecated_source_construct')
        self.assertEqual(
            _MODULE.classify_failure('', 'unsupported State field: deprecated kerberos_ticket_events'),
            'deprecated_source_construct')

    def test_canonical_and_source_type_holds_are_distinct(self):
        self.assertEqual(
            _MODULE.classify_failure('', 'unbound external Variable or unsupported possible_restriction'),
            'canonical_input_constraint_hold')
        self.assertEqual(
            _MODULE.classify_failure('', "invalid int literal: 'abc'"),
            'source_typed_literal_invalid')
        self.assertEqual(
            _MODULE.classify_failure('', 'policy source literal must be nonnegative'),
            'source_typed_literal_invalid')

    def test_source_variable_datatype_mismatch_is_not_a_converter_gap(self):
        raw = b"""<oval_definitions xmlns=\"http://oval.mitre.org/XMLSchema/oval-definitions-5\">
  <objects><environmentvariable58_object id=\"obj:1\"><pid datatype=\"int\" var_ref=\"var:1\"/></environmentvariable58_object></objects>
  <variables><constant_variable id=\"var:1\" datatype=\"boolean\"><value>true</value></constant_variable></variables>
</oval_definitions>"""
        mismatches = _MODULE.source_variable_datatype_mismatches(raw)
        self.assertEqual(mismatches, [{
            'kind': 'entity_variable_reference', 'element': 'pid',
            'element_id': '', 'variable_id': 'var:1',
            'entity_datatype': 'int', 'declared_datatype': 'boolean',
            'variable_datatype': 'boolean',
        }])

    def test_expression_result_mismatch_is_source_invalid_evidence(self):
        raw = b"""<oval_definitions xmlns=\"http://oval.mitre.org/XMLSchema/oval-definitions-5\">
  <definitions><definition id=\"def:1\"><criteria><criterion test_ref=\"tst:1\"/></criteria></definition></definitions>
  <tests><variable_test id=\"tst:1\"><object object_ref=\"obj:1\"/><state state_ref=\"ste:1\"/></variable_test></tests>
  <objects><variable_object id=\"obj:1\"><var_ref>var:1</var_ref></variable_object></objects>
  <states><variable_state id=\"ste:1\"><value>3</value></variable_state></states>
  <variables><local_variable id=\"var:1\" datatype=\"string\"><time_difference format_2=\"seconds_since_epoch\"><literal_component>1</literal_component></time_difference></local_variable></variables>
</oval_definitions>"""
        mismatches = _MODULE.source_variable_datatype_mismatches(raw)
        self.assertEqual(len(mismatches), 1)
        self.assertEqual(mismatches[0]["kind"], "variable_expression_result")
        self.assertEqual(mismatches[0]["declared_datatype"], "string")
        self.assertEqual(mismatches[0]["expression_result_datatype"], "int")

    def test_definition_scope_does_not_inherit_unrelated_file_mismatch(self):
        raw = b"""<oval_definitions xmlns=\"http://oval.mitre.org/XMLSchema/oval-definitions-5\">
  <definitions>
    <definition id=\"def:good\"><criteria><criterion test_ref=\"tst:good\"/></criteria></definition>
    <definition id=\"def:bad\"><criteria><criterion test_ref=\"tst:bad\"/></criteria></definition>
  </definitions>
  <tests><variable_test id=\"tst:good\"><object object_ref=\"obj:good\"/></variable_test><variable_test id=\"tst:bad\"><object object_ref=\"obj:bad\"/></variable_test></tests>
  <objects><variable_object id=\"obj:good\"><var_ref>var:good</var_ref></variable_object><variable_object id=\"obj:bad\"><var_ref>var:bad</var_ref></variable_object></objects>
  <variables><local_variable id=\"var:good\" datatype=\"int\"><literal_component datatype=\"int\">1</literal_component></local_variable><local_variable id=\"var:bad\" datatype=\"string\"><time_difference format_2=\"seconds_since_epoch\"><literal_component>1</literal_component></time_difference></local_variable></variables>
</oval_definitions>"""
        mismatches = _MODULE.source_variable_datatype_mismatches(raw)
        self.assertEqual(len(mismatches), 1)
        self.assertEqual(
            {row["variable_id"] for row in mismatches
             if row["variable_id"] in _MODULE.source_definition_variable_ids(raw, "def:good")},
            set())
        self.assertEqual(
            {row["variable_id"] for row in mismatches
             if row["variable_id"] in _MODULE.source_definition_variable_ids(raw, "def:bad")},
            {"var:bad"})
        self.assertEqual(
            _MODULE.classify_failure('', 'Variable cast outside bounded proof',
                                     source_mismatches=mismatches),
            'source_invalid_var_ref_datatype')
        self.assertEqual(
            _MODULE.classify_failure('', 'deprecated source capability',
                                     source_mismatches=mismatches),
            'deprecated_source_construct')

    def test_missing_source_capability_is_canonical_gap_when_pack_is_checked(self):
        message = "unsupported test capability: {http://oval.mitre.org/XMLSchema/oval-definitions-5#ios}version55_test"
        self.assertEqual(
            _MODULE.classify_failure('', message,
                                     supported_source_capabilities={"test": {"version_test"}}),
            'canonical_capability_gap')
        self.assertEqual(
            _MODULE.classify_failure('', message,
                                     supported_source_capabilities={"test": {"version55_test"}}),
            'unsupported')

    def test_traversal_schema_hold_is_distinct_from_generic_validation(self):
        self.assertEqual(
            _MODULE.classify_failure(
                '', "generated authoring failed flat JSON Schema: traversal max_depth"),
            'canonical_traversal_schema_hold')

    def test_unknown_remains_converter_failure(self):
        self.assertEqual(_MODULE.classify_failure('', 'unexpected internal diagnostic'),
                         'converter_failure')


if __name__ == '__main__':
    unittest.main()
