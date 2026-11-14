"""Issue #69: retain the remaining 23 collected-field holds."""
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import unittest

from scap_ng_tools.converter._v04_semantic import v04_variable_expressions as semantic
from scap_ng_tools.converter.native041_function_lowering import lower_expression
from scap_ng_tools.converter._v04_semantic.v04_comparison_types import predicate_type

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / 'docs/evidence/issue59/remaining-23-collected-field-audit.json'
OPERATION_LEDGER = ROOT / 'docs/evidence/issue59/operation-directed-recovery.json'
OPERATION_RECEIPT = ROOT / 'docs/evidence/issue59/full65-operation-directed-source-rule-rebuild.json'


class _CandidateSchema:
    def iter_errors(self, declaration):
        return iter(())


class RemainingCollectedAudit(unittest.TestCase):
    def test_all_source_statuses_blockers_and_families_are_preserved(self):
        report = json.loads(AUDIT.read_text())
        self.assertEqual(report['source_regressions'], 23)
        self.assertEqual(report['distinct_source_shapes'], 20)
        self.assertEqual(report['family_counts'], {
            'independent.environmentvariable': 4,
            'independent.shellcommand': 13,
            'windows.registry': 6,
        })
        self.assertEqual(report['recovered'], 0)
        self.assertEqual(report['retained_blocked'], 23)
        self.assertEqual(len({(r['benchmark'], r['source_rule']) for r in report['records']}), 23)
        for row in report['records']:
            self.assertEqual(row['original_status'], {'from': 'converted', 'to': 'blocked'})
            self.assertIn('ambiguous/empty', row['original_blocker'])
            self.assertFalse(row['explicit_source_conversion'])
            self.assertEqual(row['decision'], 'retain_blocker')
            self.assertFalse(row['item_state_evidence']['item'] == 'string')

    def test_operation_directed_receipt_preserves_holds_and_source_identity(self):
        ledger = json.loads(OPERATION_LEDGER.read_text())
        receipt = json.loads(OPERATION_RECEIPT.read_text())
        self.assertEqual(receipt['candidate'],
                         {'blocked': 98, 'converted': 6489, 'manual_only': 1403})
        self.assertEqual(receipt['newly_blocked_from_converted'], 0)
        self.assertTrue(receipt['nonregression_pass'])
        self.assertFalse(receipt['scanner_equivalent'])
        self.assertEqual(ledger['recovery_counts']['datatype_hold_records'], 108)
        self.assertEqual(ledger['candidate_receipt']['candidate'], receipt['candidate'])
        held = [row for row in ledger['records'] if row.get('decision') == 'blocked']
        self.assertEqual(len(held), 108)
        self.assertEqual(len({(row['benchmark'], row['source_rule']) for row in held}), 108)
        for row in held:
            self.assertEqual(row['operation_directed_candidate_status'], 'converted')
            self.assertTrue(row['source_status_provenance_preserved'])
            self.assertFalse(row['raw_collected_values_rewritten'])
            self.assertFalse(row['implicit_cast_added'])

    def test_typed_consumer_supplies_requested_interpretation_without_rewriting_values(self):
        allowed = {'string', 'integer', 'float', 'boolean'}
        assessment = {'variables': {'captured': {'kind': 'local', 'expression': {
            'values': {'object': {'capability': 'windows.registry'}, 'field': 'value'}}}}}
        self.assertEqual(predicate_type(
            {'datatype': 'integer', 'greater_than': {'variable': 'captured'}},
            allowed, assessment, '/test/value',
            variable_types={'captured': semantic.DYNAMIC_COLLECTED}), 'integer')
        self.assertEqual(predicate_type(
            {'datatype': 'string', 'equals': {'variable': 'captured'}},
            allowed, assessment, '/test/value',
            variable_types={'captured': semantic.DYNAMIC_COLLECTED}), 'string')
        with self.assertRaisesRegex(ValueError, 'explicit typed consumer'):
            predicate_type({'equals': {'variable': 'captured'}}, allowed, assessment,
                           '/test/value', variable_types={'captured': semantic.DYNAMIC_COLLECTED})

    def test_converter_preserves_source_consumer_datatype_on_variable_predicate(self):
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_converter import AssessmentConverter  # noqa: E402
        from v04_direct_scap_source import OVAL  # noqa: E402
        import xml.etree.ElementTree as ET
        visitor = AssessmentConverter(None, None, [], native_recovery=True)
        visitor.operand = lambda element, enum_aliases=None: {'variable': 'captured'}
        mapping = {'capability': 'independent.environmentvariable', 'native': {
            'state_field_map': {'value': 'value'},
            'field_datatypes': {'value': ['string', 'integer']},
        }}
        element = ET.fromstring(
            '<value xmlns="' + OVAL + '#independent" datatype="int" '
            'operation="greater than" var_ref="source" var_check="all" entity_check="all"/>')
        result = visitor.predicate(element, mapping)
        self.assertEqual(result['datatype'], 'integer')
        self.assertEqual(result['greater_than'], {'variable': 'captured'})
        self.assertEqual(result['value_match'], 'every')

    def test_operation_directed_consumer_does_not_rewrite_raw_values_or_status_contract(self):
        # The authoring representation carries the collection projection and
        # the requested consumer datatype separately. It must not turn lexical
        # samples (including malformed/empty values) into literals or change
        # the source collection's status/cardinality contract.
        expression = {
            'values': {
                'object': {'capability': 'independent.shellcommand',
                           'command': 'printf 123\nprintf 001\nprintf abc'},
                'field': 'subexpression',
            }
        }
        assessment = {'variables': {'captured': {'kind': 'local',
            'expression': expression}}}
        with patch.object(semantic, 'declaration_validator', return_value=_CandidateSchema()), \
             patch.object(semantic, 'snapshot', return_value=SimpleNamespace(schema_root=Path('.'))), \
             patch('scap_ng_tools.converter._v04_semantic.v04_object_contract.object_validator',
                   return_value=SimpleNamespace(iter_errors=lambda _: iter(()))), \
             patch.object(semantic, 'contract', return_value=(
                 {'subexpression': ['string', 'integer']}, set(), {}, {})), \
             patch.object(semantic, 'capability_contract', return_value=(
                 {'native': {'field_datatypes': {'subexpression': ['string', 'integer']} }},
                 {'fields': {'subexpression': ['string', 'integer']}, 'records': [],
                  'selectors': {}, 'native': {}})):
            derived = semantic.assessment_variable_expressions(assessment)
        self.assertEqual(derived['captured'], semantic.DYNAMIC_COLLECTED)
        self.assertEqual(expression['values']['field'], 'subexpression')
        self.assertNotIn('literal', expression)
        self.assertEqual(predicate_type(
            {'datatype': 'integer', 'greater_than': {'variable': 'captured'},
             'value_match': 'every'},
            {'string', 'integer'}, assessment, '/test/value',
            variable_types=derived), 'integer')
        # No status, multiplicity, or ordering information is synthesized by
        # the type gate; those remain runtime/source-evidence obligations.
        self.assertNotIn('cast', expression)
        self.assertNotIn('status', expression)

    def test_textual_function_consumers_establish_only_a_lexical_output(self):
        # The function operation, not the collected Item declaration, is the
        # source-justified text boundary. Raw collection expressions remain
        # unchanged and no cast node is authored.
        with patch.object(semantic, 'declaration_validator', return_value=_CandidateSchema()), \
             patch.object(semantic, 'snapshot', return_value=SimpleNamespace(schema_root=Path('.'))), \
             patch('scap_ng_tools.converter._v04_semantic.v04_object_contract.object_validator',
                   return_value=SimpleNamespace(iter_errors=lambda _: iter(()))), \
             patch.object(semantic, 'contract', return_value=(
                 {'subexpression': ['string', 'integer']}, set(), {}, {})), \
             patch.object(semantic, 'capability_contract', return_value=(
                 {'native': {'field_datatypes': {'subexpression': ['string', 'integer']} }},
                 {'fields': {'subexpression': ['string', 'integer']}, 'records': [],
                  'selectors': {}, 'native': {}})):
            values = {'values': {'object': {'capability': 'independent.shellcommand'},
                                  'field': 'subexpression'}}
            for op, payload in (
                ('split', {'value': values, 'delimiter': ' '}),
                ('substring', {'value': values, 'substring_start': 1,
                               'substring_length': 1}),
                ('begin', {'value': values, 'character': '/'}),
                ('end', {'value': values, 'character': '/'}),
            ):
                with self.subTest(operation=op):
                    source = {op: payload}
                    lowered = lower_expression(source)
                    assessment = {'variables': {'captured': {'kind': 'local',
                        'expression': lowered}}}
                    result = semantic.assessment_variable_expressions(assessment)
                    self.assertEqual(result['captured'], 'string')
                    self.assertEqual(lowered[op]['value']['concat'][1], values)
                    self.assertNotIn('cast', lowered)

    def test_operation_directed_consumer_conflicts_fail_closed(self):
        assessment = {'variables': {'captured': {'kind': 'local', 'expression': {
            'values': {'object': {'capability': 'windows.registry'}, 'field': 'value'}}}}}
        with self.assertRaisesRegex(ValueError, 'conflicts with capability contract'):
            predicate_type(
                {'datatype': 'boolean', 'equals': {'variable': 'captured'}},
                {'string', 'integer'}, assessment, '/test/value',
                variable_types={'captured': semantic.DYNAMIC_COLLECTED})

    def test_broad_item_domains_retain_raw_domain_until_consumer(self):
        domains = ['string', 'boolean', 'integer', 'float', 'binary', 'version',
                   'ipv4', 'ipv6', 'rpm_evr', 'debian_evr', 'fileset_revision',
                   'ios_version']
        cases = (
            ('independent.shellcommand', 'subexpression'),
            ('windows.registry', 'value'),
            ('independent.environmentvariable', 'value'),
        )
        with patch.object(semantic, 'declaration_validator', return_value=_CandidateSchema()), \
             patch.object(semantic, 'snapshot', return_value=SimpleNamespace(schema_root=Path('.'))), \
             patch('scap_ng_tools.converter._v04_semantic.v04_object_contract.object_validator',
                   return_value=SimpleNamespace(iter_errors=lambda _: iter(()))):
            for capability, field in cases:
                with self.subTest(capability=capability):
                    generated = {'fields': {field: domains}, 'records': [],
                                 'selectors': {}, 'native': {}}
                    mapping = {'native': {'field_datatypes': {field: domains}}}
                    assessment = {'variables': {'captured': {'kind': 'local', 'expression': {
                        'values': {'object': {'capability': capability}, 'field': field}}}}}
                    with patch.object(semantic, 'contract', return_value=(generated['fields'], set(), {}, generated['native'])), \
                         patch.object(semantic, 'capability_contract', return_value=(mapping, generated)):
                        result = semantic.assessment_variable_expressions(assessment)
                        self.assertEqual(result['captured'], semantic.DYNAMIC_COLLECTED)


if __name__ == '__main__':
    unittest.main()
