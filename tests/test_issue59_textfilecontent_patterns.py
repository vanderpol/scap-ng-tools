"""Issue #59: textfilecontent subexpression remains fail-closed without a cast."""
import json
from pathlib import Path
import unittest

from scap_ng_tools.converter._v04_semantic import v04_variable_expressions as semantic
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = ROOT / 'docs/evidence/issue59/textfilecontent-subexpression-patterns.json'


class _CandidateSchema:
    def iter_errors(self, declaration):
        return iter(())


class TextfilecontentPatternReview(unittest.TestCase):
    def test_all_distinct_patterns_retain_the_blocker(self):
        review = json.loads(PATTERNS.read_text())
        self.assertEqual(review['source_regressions'], 85)
        self.assertEqual(review['distinct_source_patterns'], 20)
        self.assertEqual(review['recovered'], 0)
        self.assertEqual(review['retained_blocked'], 85)
        self.assertEqual(sum(len(row['rules']) for row in review['patterns']), 85)
        self.assertTrue(all(row['decision'] == 'retain_blocker' for row in review['patterns']))
        self.assertTrue(all(row['pattern_attributes'].get('operation') == 'pattern match'
                            for row in review['patterns']))

    def test_numeric_capture_and_source_int_declaration_do_not_cast_item(self):
        # A digit-only regex and OVAL datatype="int" constrain source
        # Variable validity, but the Item subexpression remains AnySimple.
        generated = {'fields': {'subexpression': [
            'string', 'boolean', 'integer', 'float', 'binary', 'version',
            'ipv4', 'ipv6', 'rpm_evr', 'debian_evr', 'fileset_revision',
            'ios_version']}, 'records': [], 'selectors': {}, 'native': {}}
        mapping = {'native': {'field_datatypes': {
            'subexpression': ['string', 'boolean', 'integer', 'float', 'binary',
                              'version', 'ipv4', 'ipv6', 'rpm_evr', 'debian_evr',
                              'fileset_revision', 'ios_version']}}}
        assessment = {'variables': {'gid': {'kind': 'local', 'expression': {'values': {
            'object': {'capability': 'independent.textfilecontent',
                       'full_path': '/etc/group', 'pattern': '^[^:]+:(\\d+)$'},
            'field': 'subexpression'}}}}}
        with patch.object(semantic, 'declaration_validator', return_value=_CandidateSchema()), \
             patch.object(semantic, 'snapshot', return_value=SimpleNamespace(schema_root=Path('.'))), \
             patch.object(semantic, 'contract', return_value=(generated['fields'], set(), {}, generated['native'])), \
             patch.object(semantic, 'capability_contract', return_value=(mapping, generated)), \
             patch('scap_ng_tools.converter._v04_semantic.v04_object_contract.object_validator',
                   return_value=SimpleNamespace(iter_errors=lambda _: iter(()))):
            with self.assertRaisesRegex(ValueError, 'ambiguous/empty'):
                semantic.assessment_variable_expressions(assessment)


if __name__ == '__main__':
    unittest.main()
