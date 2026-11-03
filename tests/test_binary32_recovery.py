"""Exact binary32 boundaries and original-source opt-in recovery, not a scanner."""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest

from scap_ng_tools.converter.binary32 import (CONTRACT_SHA256, OPERATIONS, compare_observed,
    expected_bits, finite_literal, lexical_bits, require_contract)
from test_float_investigation import script, fields

BASE = Path(__file__).resolve().parents[1]


class Binary32Numbers(unittest.TestCase):
    def test_exact_vectors_and_double_rounding_boundary(self):
        root = os.environ.get('SCAP_NG_BINARY32_SCHEMA_ROOT') or os.environ.get('SCAP_NG_SCHEMA_ROOT')
        if not root:
            self.skipTest('Exact coordinated canonical snapshot required')
        vectors = json.loads((Path(root)/'tests/fixtures/binary32-vectors.json').read_text())
        for row in vectors:
            self.assertEqual(f'{lexical_bits(row["lexical"]):08x}', row['bits'])
        source = '1.0000000596046447753906250000000001'
        self.assertEqual(lexical_bits(source), 0x3f800001)
        self.assertEqual(struct.pack('!f', float(source)).hex(), '3f800000')

    def test_all_six_comparisons_and_nonfinite_observed_boundaries(self):
        relations = {'equals': (False, True, False), 'not_equal': (True, False, True),
            'less_than': (True, False, False), 'less_than_or_equal': (True, True, False),
            'greater_than': (False, False, True), 'greater_than_or_equal': (False, True, True)}
        for operation in OPERATIONS:
            for observed, expected in zip(('9.5', '10', '10.5'), relations[operation]):
                self.assertEqual(compare_observed(observed, operation, 10.0), expected)
            self.assertEqual(compare_observed('NaN', operation, 10.0), operation == 'not_equal')
        self.assertTrue(compare_observed('INF', 'greater_than', 10.0))
        self.assertTrue(compare_observed('-INF', 'less_than', 10.0))
        self.assertTrue(compare_observed('9.9999999', 'greater_than_or_equal', 10.0))
        self.assertTrue(compare_observed('-1e-46', 'greater_than_or_equal', 0.0))
        self.assertTrue(compare_observed('-0', 'equals', 0.0))
        self.assertTrue(compare_observed('0', 'equals', -0.0))

    def test_nonfinite_expected_and_invalid_lexicals_never_become_numbers_or_missing(self):
        for text in ('INF', '-INF', 'NaN', '1e39', '-1e99999999999999999999999'):
            with self.assertRaisesRegex(ValueError, 'nonfinite expected'):
                finite_literal(text)
        for text in ('', ' ', '1.2.3', '1_0', '0x1p0', '+INF', '-NaN', 'nan', '١', '\u00a010'):
            with self.assertRaises(ValueError):
                compare_observed(text, 'equals', 0.0)
        for value in (True, '10', None, float('inf'), float('nan'), 1.2):
            with self.assertRaises(ValueError):
                expected_bits(value)
        self.assertEqual(expected_bits(finite_literal('1.2')), 0x3f99999a)
        self.assertEqual(expected_bits(-0.0), 0x80000000)

    def test_extreme_exponents_whitespace_and_error_operation(self):
        self.assertEqual(lexical_bits(' \t10.0\r\n'), 0x41200000)
        for source, bits in [('1e99999999999999999999999', 0x7f800000),
                             ('-1e-99999999999999999999999', 0x80000000),
                             ('-0e99999999999999999999999', 0x80000000)]:
            self.assertEqual(lexical_bits(source), bits)
        self.assertEqual(lexical_bits('1.1754943508222875079687365372222456778186655567720875215087517062784172594547271728515625e-38'), 0x00800000)
        self.assertEqual(lexical_bits('1.1754942807573642917278829910357665133228589927589904276829631184250030649651730385589599609375e-38'), 0x00800000)
        with self.assertRaises(ValueError):
            compare_observed('1', 'pattern_match', 1.0)

    def test_sidecar_absence_and_tamper_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root/'schema').mkdir()
            with self.assertRaises(ValueError):
                require_contract(root/'schema')
            path = root/'docs/metadata/binary32-comparison-contract.json'
            path.parent.mkdir(parents=True); path.write_text('{}')
            with self.assertRaises(ValueError):
                require_contract(root/'schema')


class Binary32SourceRecovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schema = os.environ.get('SCAP_NG_BINARY32_SCHEMA_ROOT') or os.environ.get('SCAP_NG_SCHEMA_ROOT'); sources = os.environ.get('SCAP_NG_ADDITIONAL_FIXTURES_ROOT')
        if not schema or not sources:
            raise unittest.SkipTest('Exact coordinated schema and ten signed source cases required')
        cls.schema, cls.sources = Path(schema), Path(sources)
        cls.report, cls.results = script('recover_float_cases').recover_cases(schema, sources)

    def test_all_ten_recover_with_original_default_manual_and_no_proof_upgrade(self):
        self.assertEqual(self.report['counts_before'], {'BLOCKED': 10})
        self.assertEqual(self.report['counts_after'], {'AUTOMATED_DRAFT': 10})
        self.assertEqual(self.report['recovered'], 10)
        self.assertEqual(self.report['contract']['sha256'], CONTRACT_SHA256)
        count = 0
        for result in self.results:
            for doc in result['documents'].values():
                if 'rule' in doc:
                    rule = doc['rule']; count += 1
                    self.assertEqual(rule['default_assessment_choice'], 'automated')
                    self.assertEqual(set(rule['assessment_choices']), {'automated', 'manual'})
            for row in result['ledger']['rules']:
                self.assertTrue(row['schema_validated'] and row['semantic_validated'] and row['manual'])
                self.assertFalse(row['blockers'] or row['compiled'] or row['independent_source_proof'] or row['scanner_execution'])
        self.assertEqual(count, 10)
        for row in self.report['rules']:
            self.assertTrue(row['binary32_warnings'])
            for warning in row['binary32_warnings']:
                self.assertEqual(warning['source_attributes']['datatype'], 'float')
                self.assertEqual(warning['source_attributes']['operation'], 'greater than or equal')
                self.assertIn(warning['binary32_bits'], ('41200000', '00000000'))

    def test_nineteen_typed_test_predicates_keep_effective_collection_controls(self):
        count = 0
        for result in self.results:
            for document in result['documents'].values():
                assessment = document.get('assessment', {})
                for predicate in fields(assessment.get('tests', {}), effective=True):
                    if 'float_greater_than_or_equal' in predicate:
                        count += 1
                        self.assertIs(type(predicate['float_greater_than_or_equal']), float)
                        self.assertEqual(predicate['values_found'], 'one_or_more')
                        self.assertEqual(predicate['values_matching'], 'every')
        self.assertEqual(count, 19)

    def test_public_semantic_overlay_rejects_noncanonical_float_without_schema_changes(self):
        from scap_ng_tools.contracts import FrozenSchemaSnapshot
        from scap_ng_tools.converter._v04_semantic.validation import document_errors
        snapshot = FrozenSchemaSnapshot(self.schema)
        document = deepcopy(next(d for d in self.results[0]['documents'].values()
                                 if d.get('assessment', {}).get('mode') == 'automated'))
        predicate = next(p for p in fields(document['assessment']['tests']) if 'float_greater_than_or_equal' in p)
        predicate['float_greater_than_or_equal'] = 1.2
        self.assertTrue(any(error.validator == 'binary32_comparison_contract'
                            for error in document_errors(snapshot, 'assessment', document)))
        predicate['float_greater_than_or_equal'] = finite_literal('1.2')
        self.assertEqual(list(document_errors(snapshot, 'assessment', document)), [])
        # Actual source capabilities collect subexpressions as lexical strings.
        # Existing Item/Result primitives can retain these strings unchanged;
        # internal binary32 nonfinite bits do not require a new wire value.
        from scap_ng_tools.converter._v04_semantic.validation import validator
        item_schema = validator(str(snapshot.schema_root), 'collected-item')
        for capability in ('independent.shellcommand', 'independent.textfilecontent'):
            self.assertIn('string', snapshot.supported_mapping(capability)['native']['field_datatypes']['subexpression'])
            for text in ('INF', '-INF', 'NaN', '-1e-46', '1.2.3'):
                item = {'id': 'source-item', 'capability': capability, 'status': 'exists',
                    'fields': {'subexpression': {'datatype': 'string', 'status': 'exists', 'value': text}},
                    'provenance': {'source': 'supplied lexical serialization witness'}}
                self.assertEqual(list(item_schema.iter_errors(item)), [])

    def test_default_recovery_and_frozen_strict_visitor_still_reject_original_float(self):
        from scap_ng_tools.converter.direct04 import load_runtime
        from scap_ng_tools.converter.recovery04 import _classes
        from scap_ng_tools.contracts import FrozenSchemaSnapshot
        from v04_direct_scap_source import xml_identity, digest
        snapshot = FrozenSchemaSnapshot(self.schema); engine = load_runtime()
        Source, Visitor = _classes(engine)
        row = json.loads((BASE/'tests/fixtures/issue14-float-pins.json').read_text())[0]
        model = Source(self.sources/row['filename'], row['sha256'], inventory_broken_references=True, draft_compatibility=True)
        cid, _, _ = model.automated_check(model.rules[row['source_rule']]); witness = row['float_entities'][0]
        parent = model.nodes[cid][witness['parent']]; node = parent[witness['child_index']]
        self.assertEqual(digest(xml_identity(node)), witness['parsed_node_sha256'])
        mappings = snapshot.supported_mappings(engine.CAPABILITIES)
        for factory in (Visitor, engine.AssessmentConverter):
            visitor = factory(model, cid, mappings)
            with self.assertRaisesRegex(ValueError, 'integer source datatype'):
                visitor.predicate(node, visitor.capability(parent, 'state'))
        _, Enabled = _classes(engine, binary32_contract=require_contract(snapshot.schema_root))
        visitor = Enabled(model, cid, mappings); mapping = visitor.capability(parent, 'state')
        for operation in OPERATIONS:
            changed = deepcopy(node); changed.set('operation', operation.replace('_', ' '))
            result = visitor.predicate(changed, mapping)
            self.assertEqual(result['float_' + operation], 10.0)
        for kind in ('variable', 'record', 'selector', 'namespace', 'extra', 'absence', 'operation'):
            changed = deepcopy(node); options = {}
            if kind == 'variable': changed.set('var_ref', 'unresolved')
            elif kind == 'record': options['record_field'] = True
            elif kind == 'selector': options['selector'] = True
            elif kind == 'namespace': changed.tag = '{urn:wrong}subexpression'
            elif kind == 'extra': changed.set('unrecognized', '1')
            elif kind == 'absence': changed.set('check_existence', 'none_exist')
            else: changed.set('operation', 'greater_than_or_equal')
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                visitor.predicate(changed, mapping, **options)
        for text in ('NaN', 'INF', '-INF', '1e39', '1.2.3'):
            changed = deepcopy(node); changed.text = text
            with self.assertRaises(ValueError):
                visitor.predicate(changed, mapping)


if __name__ == '__main__':
    unittest.main()
