"""Pinned exact original automatic benchmark admission; NOT compiler/proof."""

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scap_ng_tools.contracts import FrozenSchemaSnapshot
from scap_ng_tools.converter import convert_benchmark, convert_focused
from scap_ng_tools.converter._v04_semantic.validation import document_errors

from test_benchmark_inventory import PINS, stable_digest


EXPECTED = [
    (496, 247, 44, 'c817e8b1842cecc20fa6174551502cd2199d8ddb9019214e432f9108c193a496',
     '2b06986ff6c21ea65a0a6ee45acacf53bdd58e96925ad84be47ae39765fa1e1c',
     '233fa961e84f101107cb62c5b810aa4719309c8bb5c31bbe2e212a09676c5bf4'),
    (32, 15, 21, '7b4035676c5b5aed43a2f3c0e6dfe92b40661c6e66de9e8d12eff322e68e8cd3',
     'db1dbdcbf11065eb14cad93afcd90004e12f82b4012e2423ce5b3068ab5766b5',
     'f90aacf66975f5d3cadf4d1d941142ad2a40f8c6a4c682eab491e15b2e604a53'),
    (238, 118, 69, '5d3d4e176efed970984a60ce693a740aa0e23d767dd16041c276654cbac2ca58',
     '2d21ab8b6690f74023cf3b4f14f68164a9528b52e71196b8f7b9043c84b6467a',
     'da41d34d4c1b307097cb55c93e700e4bfa3f85950485c189d6f2f22a9f67a375'),
    (0, 0, 21, '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
     '5a9c179c112065435380c84fcd79fe83830d215e2f3f72550094777feb72fe9c',
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

    def test_535_rules_have_original_automatic_admission_and_artifact_bytes(self):
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
                self.assertEqual(coverage['summary']['statuses'].get('converted', 0), admitted)
                self.assertEqual(coverage['summary']['statuses'].get('blocked', 0), blocked)
                self.assertEqual(coverage['summary']['proof_levels'].get('source_proved', 0), 0)
                self.assertFalse(coverage['scanner_evaluated'])
                for row in coverage['rules']:
                    self.assertIn(row['proof_level'], ('none', 'authoring_validated'))
                for key, value in [('source', pin['count']), ('converted', admitted),
                                   ('blocked', blocked), ('native', n)]:
                    totals[key] += value
        self.assertEqual(totals, {'source': 535, 'converted': 380,
                                  'blocked': 155, 'native': 766})

    def test_cli_exact_common_bytes_match_original_converter(self):
        legacy_root = os.environ.get('SCAP_NG_RESEARCH_ROOT')
        if not legacy_root:
            self.skipTest('Original pinned CLI checkout needed for differential test')
        path = self.files[1]
        with tempfile.TemporaryDirectory(prefix='scapng-benchmark-differential-') as temp:
            old = Path(temp) / 'original'
            new = Path(temp) / 'portable'
            legacy_cli = [sys.executable, str(Path(legacy_root) / 'tools/v04_direct_converter.py'),
                          str(path), '--sha256', PINS[1]['sha'], '--all-rules', '--output', str(old)]
            portable_cli = [sys.executable, '-m', 'scap_ng_tools.converter.direct04',
                            '--schema-root', str(self.schema), str(path), '--sha256', PINS[1]['sha'],
                            '--all-rules', '--output', str(new)]
            for command in (legacy_cli, portable_cli):
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            originals = {p.relative_to(old).as_posix(): p.read_bytes()
                         for p in old.rglob('*') if p.is_file() and p.name != 'metrics.json'}
            emitted = {p.relative_to(new).as_posix(): p.read_bytes()
                       for p in new.rglob('*') if p.is_file() and p.name != 'conversion-scope.json'}
            self.assertEqual(originals, emitted)
            self.assertEqual(json.loads((new / 'conversion-scope.json').read_text())
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

        legacy_root = os.environ.get('SCAP_NG_RESEARCH_ROOT')
        if legacy_root:
            original_runner = '''
from pathlib import Path
import json, sys
repo = Path(sys.argv[1])
sys.path.insert(0, str(repo / 'tools'))
from validate_native_json_schemas import build_validators, document_errors
v = build_validators(repo / 'schema/v0.4.0')['assessment.schema.json']
docs = json.load(sys.stdin)
for name, document in docs.items():
    docs[name] = [[str(e.validator), list(e.absolute_path), e.message]
                  for e in document_errors(v, document)]
print(json.dumps(docs))
'''
            result = subprocess.run([sys.executable, '-c', original_runner, legacy_root],
                                    input=json.dumps(cases), text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            expected = json.loads(result.stdout)
            for name, document in cases.items():
                with self.subTest(differential=name):
                    actual = [[str(e.validator), list(e.absolute_path), e.message]
                              for e in document_errors(snapshot, 'assessment', document)]
                    self.assertEqual(actual, expected[name])


if __name__ == '__main__':
    unittest.main()
