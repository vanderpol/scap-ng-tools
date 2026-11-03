"""Original float source witnesses, precision boundaries and strict admission.

These are host arithmetic/syntax experiments, not an OVAL evaluation engine.
"""
from collections import Counter
from copy import deepcopy
from fractions import Fraction
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import unittest
import xml.etree.ElementTree as ET

BASE = Path(__file__).resolve().parents[1]


def script(name):
    spec = importlib.util.spec_from_file_location(name, BASE / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fields(node, *, effective=False):
    """Find field predicates in these source-specific Test graphs."""
    if isinstance(node, dict):
        for field in node.get('fields', {}).values():
            yield {**node.get('field_requirement', {}), **field} if effective else field
        for key, value in node.items():
            if key != 'fields':
                yield from fields(value, effective=effective)
    elif isinstance(node, list):
        for value in node:
            yield from fields(value, effective=effective)


class FloatPrecision(unittest.TestCase):
    def test_thresholds_exact_but_observed_rounding_changes_comparison(self):
        # Expectations fixed independently from IEEE-754 spacing: at 10 the
        # half-ULP is 2**-21, whereas 10 - 9.9999999 is only 1e-7.
        source = '9.9999999'
        self.assertLess(Fraction(10) - Fraction(source), Fraction(1, 2**21))
        packed = struct.pack('!f', float(source))
        self.assertEqual(packed.hex(), '41200000')
        self.assertEqual(struct.unpack('!f', packed)[0], 10.0)
        self.assertFalse(float(source) >= 10.0)
        self.assertTrue(struct.unpack('!f', packed)[0] >= 10.0)
        for threshold in (0.0, 10.0):
            self.assertEqual(struct.unpack('!f', struct.pack('!f', threshold))[0], threshold)

    def test_negative_underflow_and_signed_zero_change_zero_boundary(self):
        source = '-0.' + '0' * 45 + '1'  # -1e-46; below half minimum subnormal.
        self.assertLess(abs(Fraction(source)), Fraction(1, 2**150))
        packed = struct.pack('!f', float(source))
        self.assertEqual(packed.hex(), '80000000')
        self.assertEqual(struct.pack('!f', 0.0).hex(), '00000000')
        self.assertTrue(struct.unpack('!f', packed)[0] >= 0.0)
        self.assertFalse(float(source) >= 0.0)

    def test_positive_negative_exact_boundaries_and_no_integer_projection(self):
        for text, threshold, expected in [('9.5', 10.0, False), ('10', 10.0, True),
                                           ('10.5', 10.0, True), ('-0.5', 0.0, False),
                                           ('0', 0.0, True), ('0.5', 0.0, True)]:
            self.assertEqual(struct.unpack('!f', struct.pack('!f', float(text)))[0] >= threshold, expected)
        self.assertFalse(float('-0.5') >= 0)
        self.assertTrue(int(float('-0.5')) >= 0)  # Truncation is not a repair.

    def test_nonfinite_and_overflow_are_not_json_number_substitutions(self):
        for number in (float('inf'), float('-inf'), float('nan'), float('1e400')):
            with self.assertRaises(ValueError):
                json.dumps(number, allow_nan=False)
        with self.assertRaises(OverflowError):
            struct.pack('!f', 1e39)
        with self.assertRaises(ValueError):
            float('1.2.3')


class SourceFloatInvestigation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schema = os.environ.get('SCAP_NG_SCHEMA_ROOT')
        sources = os.environ.get('SCAP_NG_ADDITIONAL_FIXTURES_ROOT')
        if not schema or not sources:
            raise unittest.SkipTest('Exact public schema and ten original signed cases required')
        from scap_ng_tools.contracts import FrozenSchemaSnapshot
        cls.snapshot = FrozenSchemaSnapshot(schema)
        cls.report, cls.probes = script('investigate_float_comparisons').investigate(schema, sources)

    def test_reproducible_source_inventory_and_exact_before_after_ledger(self):
        evidence = json.loads((BASE / 'docs/evidence/issue14-floats/investigation.json').read_text())
        # Public manifest paths are portable; no local checkout path in evidence.
        self.assertEqual(json.loads(json.dumps(self.report)), evidence)
        self.assertEqual(self.report['counts_before'], {'BLOCKED': 10})
        self.assertEqual(self.report['counts_after'], {'BLOCKED': 10})
        self.assertEqual(self.report['recovered'], 0)
        values = Counter()
        for row in self.report['rules']:
            self.assertTrue(row['manual_preserved'])
            self.assertFalse(row['compiled'])
            self.assertFalse(row['independent_source_proof'])
            self.assertFalse(row['scanner_execution'])
            self.assertFalse(row['production_admitted'])
            self.assertFalse(row['rule_emitted'])
            self.assertTrue(any('integer source datatype' in error for error in row['blockers']))
            self.assertEqual(len(row['float_entities']), 1)
            entity = row['float_entities'][0]
            self.assertEqual(entity['attributes'], {'datatype': 'float', 'operation': 'greater than or equal'})
            values[entity['lexical_value']] += 1
        self.assertEqual(values, {'10.0': 9, '0': 1})

    def test_every_source_pattern_accepts_precision_witness_without_bounding_width(self):
        nodes = self.report['source_nodes']
        for row in self.report['rules']:
            threshold = row['float_entities'][0]['lexical_value']
            patterns = []
            for entry in row['closure'].values():
                node = nodes[entry['parsed_node_sha256']]
                kind = node[0].split('}')[-1]
                if kind == ('shellcommand_object' if threshold == '10.0' else 'textfilecontent54_object'):
                    patterns.extend(child[2] for child in node[3] if child[0].endswith('}pattern'))
            self.assertEqual(len(patterns), 2)
            for pattern in patterns:
                if threshold == '10.0':
                    sample = '/dev/sda1 9.9999999G 1G 9.9999999G'
                    match = re.search(pattern, sample)
                    self.assertIsNotNone(match)
                    self.assertEqual(match.group(1), '9.9999999')
                    self.assertEqual(len(match.groups()), 2)  # Do not erase the second capture.
                else:
                    token = '-0.' + '0' * 45 + '1'
                    match = re.search(pattern, 'Defaults timestamp_timeout=' + token)
                    self.assertIsNotNone(match)
                    self.assertEqual(match.group(1), token)
                    # The source also admits malformed numeric text: no fake zero.
                    self.assertEqual(re.search(pattern, 'Defaults timestamp_timeout=1.2.3').group(1), '1.2.3')

    def test_pinned_oval_contract_explicitly_requires_single_precision(self):
        root = os.environ.get('SCAP_NG_OVAL_ROOT')
        self.assertTrue(root, 'Pinned official OVAL source required')
        tree = ET.parse(Path(root) / 'oval-schemas/oval-common-schema.xsd')
        ns = {'x': 'http://www.w3.org/2001/XMLSchema'}
        enumeration = tree.find(".//x:simpleType[@name='SimpleDatatypeEnumeration']//x:enumeration[@value='float']", ns)
        text = ''.join(enumeration.itertext())
        self.assertIn('single-precision 32-bit', text)
        for lexical in ('INF', '-INF', 'NaN'):
            self.assertIn(lexical, text)

    def test_all_ten_native_syntax_projections_preserve_float_operator_and_defaults(self):
        from scap_ng_tools.converter._v04_semantic.validation import document_errors
        self.assertFalse(self.probes['production_admitted'])
        self.assertEqual(len(self.probes['assessments']), 10)
        receipt = json.loads((BASE / 'docs/evidence/issue14-floats/native-syntax-compilation.json').read_text())
        self.assertEqual(receipt['probe_file_sha256'], sha256((json.dumps(self.probes, indent=2, allow_nan=False) + '\n').encode()).hexdigest())
        self.assertEqual(receipt['programs'], 10)
        self.assertEqual(receipt['tests'], 19)
        self.assertFalse(receipt['production_admitted'])
        self.assertFalse(receipt['independent_source_proof'])
        self.assertFalse(receipt['scanner_execution'])
        for probe in self.probes['assessments']:
            document = probe['document']
            self.assertEqual(list(document_errors(self.snapshot, 'assessment', document)), [])
            predicates = [p for p in fields(document['assessment']['tests'], effective=True) if 'float_greater_than_or_equal' in p]
            self.assertTrue(predicates)
            for predicate in predicates:
                self.assertIs(type(predicate['float_greater_than_or_equal']), float)
                self.assertIn(predicate['float_greater_than_or_equal'], (0.0, 10.0))
                self.assertEqual(predicate['values_found'], 'one_or_more')
                self.assertEqual(predicate['values_matching'], 'every')

    def test_native_operand_type_negatives_do_not_coerce(self):
        from scap_ng_tools.converter._v04_semantic.validation import document_errors
        original = self.probes['assessments'][0]['document']
        for value in ('10.0', 'INF', '-INF', 'NaN', None, True):
            document = deepcopy(original)
            predicate = next(p for p in fields(document['assessment']['tests']) if 'float_greater_than_or_equal' in p)
            predicate['float_greater_than_or_equal'] = value
            with self.subTest(value=value):
                self.assertTrue(list(document_errors(self.snapshot, 'assessment', document)))
        document = deepcopy(original)
        predicate = next(p for p in fields(document['assessment']['tests']) if 'float_greater_than_or_equal' in p)
        predicate['datatype'] = 'float'
        self.assertEqual(list(document_errors(self.snapshot, 'assessment', document)), [])
        predicate['datatype'] = 'integer'
        self.assertTrue(list(document_errors(self.snapshot, 'assessment', document)))


if __name__ == '__main__':
    unittest.main()
