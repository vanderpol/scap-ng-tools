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
    (496, 247, 44, '8cb6cd7d1a8e2fa1824c142a08cd38ae3521d70faaf6c909d7d8bddeacac2df3',
     '2b06986ff6c21ea65a0a6ee45acacf53bdd58e96925ad84be47ae39765fa1e1c',
     '233fa961e84f101107cb62c5b810aa4719309c8bb5c31bbe2e212a09676c5bf4'),
    (32, 15, 21, '69d6606cf3b8c1e5ae943b5282ecf35a258556e5ce305b5ac1f4f9e1aa3bb10b',
     'db1dbdcbf11065eb14cad93afcd90004e12f82b4012e2423ce5b3068ab5766b5',
     'f90aacf66975f5d3cadf4d1d941142ad2a40f8c6a4c682eab491e15b2e604a53'),
    (238, 118, 69, '9094dd336ab9b77e8e301d523eb0a2cf6df65910a243ce57d553113240b853ee',
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

    def test_cli_exact_common_bytes_match_owner_amended_v04_baseline(self):
        # Old original research CLI digest before Item grouping:
        # 7720a9efae45a7ba34ca107bcdeb0face751aae8126e2e14b5c16f07c6f8d6ff
        # Preserve historic provenance, but the original YAML bytes no longer
        # qualify as current 0.4 authoring after the approved amendment.
        original_file_count = 67
        original_file_digest = 'd5a38ab93c9ffb9852a529b4de8860bbd848973963b5a2935958b6c61b1c073f'
        legacy_root = os.environ.get('SCAP_NG_RESEARCH_ROOT')
        path = self.files[1]
        with tempfile.TemporaryDirectory(prefix='scapng-benchmark-differential-') as temp:
            old = Path(temp) / 'original'
            new = Path(temp) / 'portable'
            portable_cli = [sys.executable, '-m', 'scap_ng_tools.converter.direct04',
                            '--schema-root', str(self.schema), str(path), '--sha256', PINS[1]['sha'],
                            '--all-rules', '--output', str(new)]
            commands = [portable_cli]
            if legacy_root:
                commands.insert(0, [
                    sys.executable, str(Path(legacy_root) / 'tools/v04_direct_converter.py'),
                    str(path), '--sha256', PINS[1]['sha'], '--all-rules', '--output', str(old)])
            for command in commands:
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            emitted = {p.relative_to(new).as_posix(): p.read_bytes()
                       for p in new.rglob('*') if p.is_file() and p.name != 'conversion-scope.json'}
            digest = sha256()
            for name, raw in sorted(emitted.items()):
                digest.update(name.encode('utf-8') + bytes([0]))
                digest.update(raw)
            self.assertEqual(len(emitted), original_file_count)
            self.assertEqual(digest.hexdigest(), original_file_digest)
            if legacy_root:
                originals = {p.relative_to(old).as_posix(): p.read_bytes()
                             for p in old.rglob('*') if p.is_file() and p.name != 'metrics.json'}
                def upgraded(document):
                    if isinstance(document, dict) and 'assessment' in document:
                        for test in document['assessment'].get('tests', {}).values():
                            req = test.get('require', {})
                            if 'items_found' in req:
                                item = {'items_found': req.pop('items_found')}
                                if 'items_satisfying' in req:
                                    item['items_satisfying'] = req.pop('items_satisfying')
                                test['require'] = {'item_requirement': item, **req}
                    return document
                for name, old_raw in originals.items():
                    new_raw = emitted[name]
                    if name.endswith('.json'):
                        self.assertEqual(upgraded(json.loads(old_raw)), json.loads(new_raw), name)
                    elif name.endswith('.yaml'):
                        self.assertEqual(upgraded(yaml.safe_load(old_raw)), yaml.safe_load(new_raw), name)
                    else:
                        self.assertEqual(old_raw, new_raw, name)
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
