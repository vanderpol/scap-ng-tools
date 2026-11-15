"""Pinned automatic benchmark admission with audited 0.4 authoring regeneration.

Original 2026-Q3 source and Rule provenance remain pinned. Native document
counts/digests include the owner-approved OVAL-preferred selection policy:
OCIL-only Rules are manual and OCIL is an optional alternative.
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


# Owner-approved OVAL-preferred selection now preserves OCIL-only Rules as
# manual Assessments and retains manual OCIL alternatives beside automated OVAL
# choices. These are exact regenerated native/trace/coverage digests, not proof
# of source-result equivalence.
EXPECTED = [
    (785, 241, 20, '3175e046e7f3a4a37bb4b6dfdf545e06041030fc263dcbe2ddac80520c64ae8c',
     'd3f458e9e3fb426d6cecd825518b181177dac0641d41bdafe48087744aa4716c',
     'eee4b349ccacf39ccaaa29c8ee57d72e664c7a0df4761ca5047a69b9df369d8b'),
    (85, 15, 2, 'a82001fbf1dac41044b87ee7041603bb597d77be3d7f919d94074a71cbf8a8a3',
     'f35aa22ca294ce5e54b667473fac0518f02daf454322f3ae6efc2645179fccae',
     '7b3527f3c8f04296681c33b3c50e38201ce9c4688c8a2f255bd5c52bf6a8a0f8'),
    (390, 118, 52, 'ada363bc3f830b7d426dd7920f9df08e86bcf532995257d5fdc57af9ae3cace4',
     'c97f181a0b9408a0f37627173f844c5b3305a424bb911e2917f1c9e958c7af92',
     '7b91bed3573cda432540fd137025ed4557fb72d5485c88037289f036e6760b18'),
    (4, 0, 20, '9b869db3c0581ae05a38f523ec393674ccc776653b643ecff3267ffc57607eef',
     'e21a5aa82eb48909a4bdc7b0804924aee4354194a66322c3b422e14f287da746',
     '9aa42704cc4595f86a7e0ecccc854f49c6e864a8142e9e046ae2b9f4d3c06d42'),
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
        self.assertEqual(totals, {'source': 535, 'converted': 374,
                                  'blocked': 94, 'native': 1264})

    def test_cli_exact_common_bytes_match_owner_amended_v04_baseline(self):
        # Old original research CLI digest before Item grouping:
        # 7720a9efae45a7ba34ca107bcdeb0face751aae8126e2e14b5c16f07c6f8d6ff
        # Preserve historic provenance, but the original YAML bytes no longer
        # qualify as current 0.4 authoring after the approved amendment.
        original_file_count = 173
        original_file_digest = 'd8b6659514e3e892b162d204fb21c0a8ba44a9e70ef0ee59b953396723e6a0e4'
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
        assessments = [d for d in documents.values()
                       if 'assessment' in d and d['assessment'].get('mode') == 'automated']
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
