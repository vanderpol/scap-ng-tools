"""Issue #69: retain the remaining 23 collected-field holds."""
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import unittest

from scap_ng_tools.converter._v04_semantic import v04_variable_expressions as semantic

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / 'docs/evidence/issue59/remaining-23-collected-field-audit.json'


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

    def test_broad_item_domains_remain_ambiguous_without_a_cast(self):
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
                        with self.assertRaisesRegex(ValueError, 'ambiguous/empty'):
                            semantic.assessment_variable_expressions(assessment)


if __name__ == '__main__':
    unittest.main()
