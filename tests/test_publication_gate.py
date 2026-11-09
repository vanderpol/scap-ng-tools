"""Actual publication admission and adversarial candidate tests, not filename checks."""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import yaml

from scap_ng_tools.publication.gate import (AdmissionError, canonical, prepare, read_tree,
                                           stage_historical)

REQUEST = {'mode': 'oval-definition', 'source_commit': 'e3538595c5083b9c34d937a81d319234df9bbfaa',
           'source_path': 'SCAP_1.4/OVAL_Test_Content/agnostic/oval-def_constant_variable.xml',
           'source_sha256': '57113e1d5991bec0c7cee30d2789ecf9bff5223d2f2ab78900098c187a716e91',
           'selection': 'oval:org.mitre.oval.test:def:92'}


class CurrentPublication(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs = dict(producer_root=os.environ.get('SCAP_NG_APPROVED_CONVERTER_ROOT'),
                          schema_root=os.environ.get('SCAP_NG_SCHEMA_ROOT'),
                          source_root=os.environ.get('SCAP_NG_OVAL_TEST_CONTENT'))
        if not all(cls.inputs.values()):
            if os.environ.get('SCAP_NG_PUBLICATION_REQUIRED') == '1':
                raise AssertionError('Required publication fixtures missing')
            raise unittest.SkipTest('Explicit approved producer, schema and original sources required')
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        cls.candidate = cls.root / 'current'
        prepare(**cls.inputs, request=REQUEST, output=cls.candidate)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def candidate_copy(self, directory):
        target = Path(directory) / 'candidate'
        shutil.copytree(self.candidate, target)
        return target

    def admit_cli(self, candidate, output):
        command = [sys.executable, '-m', 'scap_ng_tools.publication', 'admit',
                   '--candidate', str(candidate), '--output', str(output)]
        for key, value in self.inputs.items():
            command += ['--' + key.replace('_', '-'), value]
        return subprocess.run(command, capture_output=True, text=True, timeout=120)

    def refresh(self, candidate, change=lambda m: None):
        path = candidate / 'publication-manifest.json'
        manifest = json.loads(path.read_bytes())
        manifest['files'] = {name: {'sha256': sha256(raw).hexdigest(), 'bytes': len(raw)}
                             for name, raw in read_tree(candidate / 'payload').items()}
        change(manifest)
        raw = canonical(manifest)
        path.write_bytes(raw)
        (candidate / 'manifest.sha256').write_text(sha256(raw).hexdigest() + '\n')

    def reject(self, mutation):
        with tempfile.TemporaryDirectory() as directory:
            candidate = self.candidate_copy(directory)
            mutation(candidate)
            output = Path(directory) / 'must-not-publish.zip'
            proc = self.admit_cli(candidate, output)
            self.assertNotEqual(proc.returncode, 0, proc.stdout)
            self.assertFalse(output.exists(), 'failed admission published an archive')
            self.assertIn('publication rejected', proc.stderr)

    def test_current_converter_to_final_bytes_to_publication_dry_run(self):
        import zipfile
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'current.zip'
            proc = self.admit_cli(self.candidate, output)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            result = json.loads(proc.stdout)
            self.assertEqual(result['status'], 'ADMITTED_CURRENT_NATIVE_AUTHORING_VALIDATED')
            self.assertEqual(result['tier'], 'authoring_validated')
            self.assertFalse(result['scanner_equivalent'])
            self.assertEqual(sha256(output.read_bytes()).hexdigest(), result['archive_sha256'])
            with zipfile.ZipFile(output) as archive:
                original = json.loads(archive.read('payload/assessment.json'))
                self.assertEqual(len(original['assessment']['tests']), 2)
                self.assertEqual(len(original['assessment']['evaluate']['and']), 2)
                self.assertEqual(yaml.safe_load(archive.read('payload/assessment.yaml')), original)
                self.assertEqual(archive.read('publication-manifest.json'), (self.candidate / 'publication-manifest.json').read_bytes())

    def test_historical_and_renamed_producers_rejected_with_rehashed_manifest(self):
        for key, value in [('commit', 'a08c9beb9dcf781a726adbdf05676f5ae2e57309'),
                           ('entrypoint', 'renamed-wrapper:main'), ('dirty', True),
                           ('distribution_version', 'historical')]:
            with self.subTest(key):
                self.reject(lambda c: self.refresh(c, lambda m: m['producer'].__setitem__(key, value)))

    def test_missing_provenance_and_wrong_schema_digest_rejected(self):
        self.reject(lambda c: self.refresh(c, lambda m: m['producer'].pop('commit')))
        self.reject(lambda c: self.refresh(c, lambda m: m['schema'].__setitem__('family_sha256', '0' * 64)))

    def test_post_validation_byte_mutation_rejected(self):
        self.reject(lambda c: (c / 'payload/assessment.yaml').write_bytes((c / 'payload/assessment.yaml').read_bytes() + b'\n# changed\n'))

    def test_obsolete_require_rejected_even_with_matching_json_yaml_hashes(self):
        def mutate(candidate):
            path = candidate / 'payload/assessment.json'
            doc = json.loads(path.read_bytes())
            for test in doc['assessment']['tests'].values():
                q = test['require']
                q.update(q.pop('item_requirement'))
            path.write_text(json.dumps(doc))
            (candidate / 'payload/assessment.yaml').write_text(yaml.safe_dump(doc))
            self.refresh(candidate)
        self.reject(mutate)

    def test_actual_preserved_historical_variable_output_cannot_be_laundered(self):
        fixture = Path(__file__).parent / 'fixtures/publication'
        provenance = json.loads((fixture / 'provenance.json').read_text())
        raw = (fixture / 'obsolete-variable-assessment.json').read_bytes()
        self.assertEqual(sha256(raw).hexdigest(), provenance['files']['obsolete-variable-assessment.json']['sha256'])
        def mutate(candidate):
            (candidate / 'payload/assessment.json').write_bytes(raw)
            (candidate / 'payload/assessment.yaml').write_text(yaml.safe_dump(json.loads(raw)))
            # A wrapper may rename the producer and refresh every claimed hash;
            # the actual historical native document still fails admission.
            self.refresh(candidate)
        self.reject(mutate)

    def test_duplicate_yaml_keys_and_json_yaml_disagreement_rejected(self):
        def duplicate(candidate):
            path = candidate / 'payload/assessment.yaml'
            path.write_bytes(b'assessment: {}\n' + path.read_bytes())
            self.refresh(candidate)
        self.reject(duplicate)
        def disagree(candidate):
            path = candidate / 'payload/assessment.yaml'
            doc = yaml.safe_load(path.read_bytes())
            doc['assessment']['assessment_title'] = 'swapped after schema validation'
            path.write_text(yaml.safe_dump(doc))
            self.refresh(candidate)
        self.reject(disagree)

    def test_schema_valid_swapped_bytes_and_forged_hashes_fail_reproduction(self):
        def mutate(candidate):
            for extension in ('json', 'yaml'):
                source = Path(self.inputs['producer_root']) / 'docs/evidence/issue37-variables/oval-def_variable_component' / ('assessment.' + extension)
                (candidate / 'payload' / ('assessment.' + extension)).write_bytes(source.read_bytes())
            self.refresh(candidate)
        self.reject(mutate)

    def test_cannot_promote_authoring_to_source_runtime_or_full65_proof(self):
        for field in ('source_proved', 'ri_executed', 'scanner_equivalent', 'full_65_complete'):
            with self.subTest(field):
                self.reject(lambda c: self.refresh(c, lambda m: m['qualification'].__setitem__(field, True)))
        self.reject(lambda c: self.refresh(c, lambda m: m['qualification'].__setitem__('source_proved', 0)))
        with tempfile.TemporaryDirectory() as directory:
            request = dict(REQUEST, mode='full-65')
            with self.assertRaisesRegex(AdmissionError, 'no qualified full-65'):
                prepare(**self.inputs, request=request, output=Path(directory) / 'blocked')
            self.assertFalse((Path(directory) / 'blocked').exists())

    def test_actual_dirty_or_unapproved_producer_checkout_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory) / 'producer'
            subprocess.run(['git', 'clone', '--quiet', '--no-checkout', '--shared', '--local',
                            self.inputs['producer_root'], str(clone)], check=True, capture_output=True)
            subprocess.run(['git', '-C', str(clone), 'checkout', '--quiet', '--detach',
                            'f97ff187460f52da78bd16f5009f7d182664812b'], check=True, capture_output=True)
            shadow = clone / 'untracked-wrapper.py'
            shadow.write_text('# unapproved executable\n')
            for state in ('dirty', 'old-revision'):
                with self.subTest(state), self.assertRaises(AdmissionError):
                    prepare(**dict(self.inputs, producer_root=clone), request=REQUEST,
                            output=Path(directory) / ('blocked-' + state))
                if state == 'dirty':
                    shadow.unlink()
                    # A shallow CI checkout need not contain old history. An
                    # otherwise identical, unapproved commit must also reject.
                    subprocess.run(['git', '-C', str(clone), '-c', 'user.name=Publication fixture',
                                    '-c', 'user.email=publication-fixture@example.invalid',
                                    'commit', '--quiet', '--allow-empty', '-m', 'Unapproved test-only producer revision'],
                                   check=True, capture_output=True)

    def test_legacy_direct_publication_is_nonzero(self):
        proc = subprocess.run([sys.executable, '-m', 'scap_ng_tools.publication', 'deny-legacy-publication'],
                              capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('legacy direct publication is blocked', proc.stderr)


class HistoricalPublication(unittest.TestCase):
    def test_preserves_proof_bytes_and_original_relative_paths_without_promotion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'proofs'
            source.mkdir()
            (source / 'original-proof.json').write_text('{"historical_static_proof":true}\n')
            (source / 'native.yaml').write_text('historical: unchanged\n')
            result = stage_historical(patterns=str(source), output=root / 'staged', receipt=root / 'receipt.json')
            self.assertEqual(read_tree(source), read_tree(root / 'staged'))
            receipt = json.loads((root / 'receipt.json').read_bytes())
            self.assertFalse(receipt['current_native'])
            self.assertEqual(receipt['tier'], 'historical_unqualified')
            self.assertEqual(result['status'], 'HISTORICAL_DRAFT_UNQUALIFIED')

    def test_globs_exclusions_and_missing_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'input'
            source.mkdir()
            for name in ('one.json', 'two.json', 'not-selected.txt'):
                (source / name).write_text(name)
            stage_historical(patterns=str(source / '*.json') + '\n!' + str(source / 'two.json'),
                             output=root / 'out', receipt=root / 'receipt.json')
            self.assertEqual(set(read_tree(root / 'out')), {'one.json'})
            with self.assertRaises(AdmissionError):
                stage_historical(patterns=str(source / 'absent.*'), output=root / 'no', receipt=root / 'no.json')

    def test_symlink_and_path_escape_are_not_published(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'original').write_text('private input')
            (root / 'link').symlink_to(root / 'original')
            with self.assertRaises(AdmissionError):
                stage_historical(patterns=str(root / 'link'), output=root / 'out', receipt=root / 'receipt.json')
