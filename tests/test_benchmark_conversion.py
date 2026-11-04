"""Pinned automatic benchmark admission with audited 0.4 authoring regeneration.

Original 2026-Q3 source, trace, coverage and Rule acceptance are unchanged;
only native document serialization changes with owner-approved Item grouping.
No compiler/scanner proof is asserted.
"""

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import yaml

from scap_ng_tools.contracts import FrozenSchemaSnapshot
from scap_ng_tools.converter import convert_benchmark, convert_focused

from test_benchmark_inventory import PINS, stable_digest


EXPECTED = [
    (496, 247, 44, '5687a4919b66e4e38e9d9dc2f59131393cf9683b0af768caf0ca4c3fa72deca8',
     '28ccb0600d666f99b76b36164776a7b442276ef8282f614d87b28c470dcf95d4',
     '233fa961e84f101107cb62c5b810aa4719309c8bb5c31bbe2e212a09676c5bf4'),
    (32, 15, 21, '69d6606cf3b8c1e5ae943b5282ecf35a258556e5ce305b5ac1f4f9e1aa3bb10b',
     '450aadbc110a26934a5688aefbed0c86e0e967ead6e1041cbc376e858f7dee64',
     'f90aacf66975f5d3cadf4d1d941142ad2a40f8c6a4c682eab491e15b2e604a53'),
    (238, 118, 69, '7a9a7b578bf6f7f3498e58369f64340c719f7b50e5a376058974aefa20f6db4d',
     '09d77b842843d3cab5b3dd4e9e28af253799ac3878608cd65239dc47a8d880e2',
     'da41d34d4c1b307097cb55c93e700e4bfa3f85950485c189d6f2f22a9f67a375'),
    (0, 0, 21, '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
     'fde316371acb5b11e9f5b747b3138ec66e5ea07dc8609e6480543d2f0a7210bc',
     '5e70d08b2503940e2f486529164f65108c9a3a101a358ba2d0e37f16287d8d0d'),
]


class BenchmarkConversionParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schema = os.environ.get('SCAP_NG_SCHEMA_ROOT')
        primary = os.environ.get('SCAP_NG_SOURCE_FIXTURE')
        others = os.environ.get('SCAP_NG_ADDITIONAL_FIXTURES_ROOT')
        if not all((schema, primary, others)):
            raise unittest.SkipTest('Explicit original source and flat schema fixtures required')
        cls.schema = Path(schema)
        cls.files = [Path(primary)] + [Path(others) / pin['filename'] for pin in PINS[1:]]

    def test_535_rules_preserve_admission_and_regenerated_document_hashes(self):
        totals = {'source': 0, 'converted': 0, 'blocked': 0, 'native': 0}
        for path, pin, (n, admitted, blocked, docs_hash, trace_hash, coverage_hash) in zip(
                self.files, PINS, EXPECTED):
            with self.subTest(source=path.name):
                self.assertEqual(sha256(path.read_bytes()).hexdigest(), pin['sha'])
                documents, trace, coverage = convert_benchmark(
                    schema_root=self.schema, source=path, sha256_pin=pin['sha'])
                self.assertEqual(len(documents), n)
                self.assertEqual(stable_digest(documents), docs_hash)
                self.assertEqual(stable_digest(trace), trace_hash)
                self.assertEqual(stable_digest(coverage), coverage_hash)
                self.assertEqual(coverage['summary']['source_rules'], pin['count'])
                # Reconcile totals before independent golden assertions so
                # parity drift cannot mask the observed 535 source Rules.
                totals['source'] += pin['count']
                totals['converted'] += admitted
                totals['blocked'] += blocked
                totals['native'] += n
                self.assertEqual(coverage['summary']['statuses'].get('converted', 0), admitted)
                self.assertEqual(coverage['summary']['statuses'].get('blocked', 0), blocked)
                self.assertEqual(coverage['summary']['proof_levels'].get('source_proved', 0), 0)
                self.assertFalse(coverage['scanner_evaluated'])
                for row in coverage['rules']:
                    self.assertIn(row['proof_level'], ('none', 'authoring_validated'))
        self.assertEqual(totals, {'source': 535, 'converted': 380,
                                  'blocked': 155, 'native': 766})

    def test_cli_exact_common_bytes_match_owner_amended_v04_baseline(self):
        # Old original research CLI digest before Item grouping:
        # 7720a9efae45a7ba34ca107bcdeb0face751aae8126e2e14b5c16f07c6f8d6ff
        # Preserve historic provenance, but the original YAML bytes no longer
        # qualify as current 0.4 authoring after the approved amendment.
        original_file_count = 67
        original_file_digest = '5fc696189a0e134077d46e46143e21b4b5637b635e43c12106b1d9b83509b3e5'
        path = self.files[1]
        with tempfile.TemporaryDirectory(prefix='scapng-benchmark-portable-') as temp:
            output = Path(temp) / 'portable'
            result = subprocess.run([
                sys.executable, '-m', 'scap_ng_tools.converter.direct04',
                '--schema-root', str(self.schema), str(path), '--sha256', PINS[1]['sha'],
                '--all-rules', '--output', str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            emitted = {p.relative_to(output).as_posix(): p.read_bytes()
                       for p in output.rglob('*') if p.is_file() and p.name != 'conversion-scope.json'}
            digest = sha256()
            for name, raw in sorted(emitted.items()):
                digest.update(name.encode('utf-8') + bytes([0]))
                digest.update(raw)
            self.assertEqual(len(emitted), original_file_count)
            self.assertEqual(digest.hexdigest(), original_file_digest)
            self.assertEqual(json.loads((output / 'conversion-scope.json').read_text())
                             ['independent_semantic_proof'], False)

    def test_unqualified_modes_never_create_benchmark_output(self):
        with tempfile.TemporaryDirectory(prefix='scapng-unqualified-modes-') as temp:
            for flag in ('--verify', '--compile', '--draft'):
                with self.subTest(flag=flag):
                    target = Path(temp) / flag.removeprefix('--')
                    result = subprocess.run([
                        sys.executable, '-m', 'scap_ng_tools.converter.direct04',
                        '--schema-root', str(self.schema), str(self.files[1]),
                        '--sha256', PINS[1]['sha'], '--all-rules', flag,
                        '--output', str(target)], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('owner-qualified ports', result.stderr)
                    self.assertFalse(target.exists())

    def test_explicit_negative_semantic_boundaries_remain_active(self):
        from scap_ng_tools.converter._v04_semantic.validation import document_errors
        documents, _ = convert_focused(
            schema_root=self.schema, source=self.files[0], sha256_pin=PINS[0]['sha'],
            rule_ids=['xccdf_mil.disa.stig_rule_SV-278139r1182083_rule',
                      'xccdf_mil.disa.stig_rule_SV-278080r1180946_rule'])
        assessments = [d for d in documents.values() if 'assessment' in d]
        shell = next(d for d in assessments if 'independent.shellcommand'
                     in {t['capability'] for t in d['assessment']['tests'].values()})
        registry = next(d for d in assessments if 'windows.registry'
                        in {t['capability'] for t in d['assessment']['tests'].values()})
        snapshot = FrozenSchemaSnapshot(self.schema)
        self.assertFalse(list(document_errors(snapshot, 'assessment', registry)))
        self.assertFalse(list(document_errors(snapshot, 'assessment', shell)))

        cases = {}
        invalid_object = deepcopy(registry)
        next(iter(invalid_object['assessment']['tests'].values()))['object']['collect'] = {'some': 'invalid'}
        cases['native_0.4_object_contract'] = invalid_object
        invalid_type = deepcopy(registry)
        next(iter(invalid_type['assessment']['tests'].values()))['require']['fields']['last_write_time'] = {'equals': 'not-an-integer'}
        cases['native_comparison_datatype'] = invalid_type
        invalid_variable = deepcopy(shell)
        next(iter(invalid_variable['assessment']['variables'].values()))['expression'] = {'variable': 'missing-variable'}
        cases['native_variable_expression'] = invalid_variable
        invalid_input = deepcopy(shell)
        invalid_input['assessment']['inputs'] = {
            'example-input': {'datatype': 'string', 'cardinality': 'zero_or_one', 'required': False}}
        next(iter(invalid_input['assessment']['tests'].values()))['object']['command'] = {'input': 'example-input'}
        cases['optional_input'] = invalid_input
        for name, document in cases.items():
            with self.subTest(gate=name):
                findings = list(document_errors(snapshot, 'assessment', document))
                self.assertTrue(findings, name)
                if name != 'optional_input':
                    self.assertIn(name, {error.validator for error in findings})
                else:
                    self.assertTrue(any('unguarded optional Input' in error.message for error in findings))




if __name__ == '__main__':
    unittest.main()
