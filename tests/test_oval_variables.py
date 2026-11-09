"""Whole original OVAL Definitions through the production facade and CLI."""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
import yaml

from scap_ng_tools.converter import convert_oval_definition
from scap_ng_tools.converter.direct04 import validate_native_documents
from scap_ng_tools.contracts import FrozenSchemaSnapshot

PIN = 'e3538595c5083b9c34d937a81d319234df9bbfaa'
PREFIX = 'SCAP_1.4/OVAL_Test_Content/agnostic/'
CASES = [
    ('oval-def_constant_variable.xml', 92, 2, 2, '57113e1d5991bec0c7cee30d2789ecf9bff5223d2f2ab78900098c187a716e91'),
    ('oval-def_variable_component.xml', 118, 2, 4, '5d32d88d7773bd89438f9afcb95f0afb9c3b9c6eca199899799b409b12abf2be'),
    ('ind-def_variable_test.xml', 538, 4, 2, '878fa0adc9e27e518fbdac75756b04ef8ed0c9facf937caf98576dc185414b85'),
    ('oval_check_enumeration_variable_values.xml', 170, 10, 2, 'cb317fa5d8073a9fe994175e4ba270857f4278c3f00bd895096147e962e6e8be'),
]
O = '{http://oval.mitre.org/XMLSchema/oval-definitions-5}'
I = O[:-1] + '#independent}'


class StandaloneVariables(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = os.environ.get('SCAP_NG_SCHEMA_ROOT')
        source = os.environ.get('SCAP_NG_OVAL_TEST_CONTENT')
        if not cls.schema or not source:
            raise unittest.SkipTest('SCAP_NG_SCHEMA_ROOT and SCAP_NG_OVAL_TEST_CONTENT required')
        cls.source = Path(source)
        cls.snapshot = FrozenSchemaSnapshot(cls.schema)

    def convert(self, case, path=None):
        file, did, _, _, digest = case
        source = path or self.source / PREFIX / file
        return convert_oval_definition(schema_root=self.schema, source=source,
            sha256_pin=sha256(source.read_bytes()).hexdigest() if path else digest,
            definition_id='oval:org.mitre.oval.test:def:' + str(did),
            source_commit=PIN, source_path=PREFIX + file)

    def test_all_eighteen_tests_are_schema_valid_complete_and_source_bound(self):
        total = 0
        for case in CASES:
            file, _, tests, variables, digest = case
            raw = (self.source / PREFIX / file).read_bytes()
            self.assertEqual(sha256(raw).hexdigest(), digest)
            docs, trace = self.convert(case)
            assessment = docs['assessment.json']['assessment']
            self.assertEqual(len(assessment['tests']), tests)
            self.assertEqual(len(assessment['variables']), variables)
            self.assertEqual(assessment['class'], 'miscellaneous')
            self.assertEqual(len(assessment['evaluate']['and']), tests)
            self.assertTrue(trace['source_commit_blob_verified'])
            self.assertEqual(trace['qualification'], 'CONVERTED_UNVERIFIED')
            self.assertFalse(trace['scanner_execution'])
            root = ET.fromstring(raw)
            original_ids = {node.get('id') for group in root for node in group if node.get('id')}
            self.assertEqual(set(trace['source_nodes']), original_ids)
            for test in assessment['tests'].values():
                self.assertNotIn('object', test)
                self.assertIn(test['variable'], assessment['variables'])
                self.assertIn('item_requirement', test['require'])
            validate_native_documents(self.snapshot, docs)
            total += tests
        self.assertEqual(total, 18)

    def test_alias_edges_and_distinct_cross_pairings_survive(self):
        docs, trace = self.convert(CASES[1])
        assessment = docs['assessment.json']['assessment']
        ids = {row['source_id']: row['native_id'] for row in trace['native_identities'] if row['kind'] == 'variable'}
        base = 'oval:org.mitre.oval.test:var:'
        self.assertEqual(assessment['variables'][ids[base + '817']]['expression'], {'variable': ids[base + '721']})
        self.assertEqual(assessment['variables'][ids[base + '866']]['expression'], {'variable': ids[base + '852']})
        docs, trace = self.convert(CASES[2])
        assessment = docs['assessment.json']['assessment']
        root = ET.parse(self.source / PREFIX / CASES[2][0]).getroot()
        originals = {node.get('id'): node for group in root for node in group if node.get('id')}
        ids = {row['source_id']: row['native_id'] for row in trace['native_identities'] if row['kind'] == 'variable'}
        pairs = []
        for binding in trace['test_bindings']:
            test = assessment['tests'][binding['native_test']]
            pair = (test['variable'], test['require']['fields']['value']['equals']['variable'])
            source_test = originals[binding['source_test']]
            obj = originals[source_test.find(I + 'object').get('object_ref')]
            state = originals[source_test.find(I + 'state').get('state_ref')]
            self.assertEqual(pair, (ids[obj.find(I + 'var_ref').text], ids[state.find(I + 'value').get('var_ref')]))
            pairs.append(pair)
            self.assertEqual(test['require']['fields']['value']['value_match'], 'one_or_more')
        self.assertEqual(len(set(pairs)), 4)
        self.assertEqual(len({left for left, _ in pairs}), 2)
        self.assertEqual(len({right for _, right in pairs}), 2)

    def test_committed_handoff_artifacts_match_sources_and_current_native_output(self):
        repository = Path(__file__).resolve().parents[1]
        manifest = json.loads((repository / 'docs/evidence/issue37-variables/manifest.json').read_text())
        self.assertEqual(manifest['source_commit'], PIN)
        self.assertEqual(manifest['original_tests_schema_validated'], 18)
        self.assertEqual(len(manifest['cases']), len(CASES))
        for case, entry in zip(CASES, manifest['cases']):
            self.assertEqual(entry['source_file'], PREFIX + case[0])
            self.assertEqual(entry['source_sha256'], case[4])
            payloads = {}
            for path, integrity in entry['artifacts'].items():
                raw = (repository / path).read_bytes()
                self.assertEqual(sha256(raw).hexdigest(), integrity['sha256'])
                self.assertEqual(len(raw), integrity['bytes'])
                payloads[Path(path).name] = raw
            doc = json.loads(payloads['assessment.json'])
            self.assertEqual(yaml.safe_load(payloads['assessment.yaml']), doc)
            validate_native_documents(self.snapshot, {'assessment.json': doc})
            current, trace = self.convert(case)
            self.assertEqual(current['assessment.json'], doc)
            recorded = json.loads(payloads['source-trace.json'])
            self.assertEqual(recorded['source_nodes'], trace['source_nodes'])
            self.assertEqual(recorded['test_bindings'], trace['test_bindings'])
            self.assertEqual(recorded['native_identities'], trace['native_identities'])

    def test_source_mutations_do_not_return_partial_conversions(self):
        original = ET.parse(self.source / PREFIX / CASES[0][0]).getroot()
        for change in ('wrong_kind', 'identity', 'cast', 'function', 'alias_cycle', 'fake_definition'):
            with tempfile.TemporaryDirectory() as directory:
                root = deepcopy(original)
                if change == 'wrong_kind':
                    root.find(O + 'tests')[0].find(I + 'object').set('object_ref', 'oval:org.mitre.oval.test:var:641')
                elif change == 'identity':
                    ET.SubElement(root.find(O + 'states')[0], I + 'var_ref').text = 'oval:org.mitre.oval.test:var:831'
                elif change == 'cast':
                    root.find(O + 'variables')[0].set('datatype', 'string')
                elif change == 'fake_definition':
                    root.find(O + 'definitions')[0].tag = O + 'unknown_definition'
                else:
                    node = root.find(O + 'variables')[0]
                    node.tag = O + 'local_variable'
                    for child in list(node):
                        node.remove(child)
                    if change == 'function':
                        ET.SubElement(node, O + 'concat')
                    else:
                        ET.SubElement(node, O + 'variable_component', {'var_ref': node.get('id')})
                path = Path(directory) / 'mutated.xml'
                ET.ElementTree(root).write(path, encoding='utf-8')
                with self.subTest(change), self.assertRaises(ValueError):
                    self.convert(CASES[0], path)

    def test_original_hash_and_declared_commit_cannot_be_substituted(self):
        file, did, _, _, digest = CASES[0]
        args = dict(schema_root=self.schema, source=self.source / PREFIX / file,
                    definition_id='oval:org.mitre.oval.test:def:' + str(did), source_path=PREFIX + file)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            convert_oval_definition(**args, sha256_pin='0' * 64, source_commit=PIN)
        with self.assertRaisesRegex(ValueError, 'commit/path'):
            convert_oval_definition(**args, sha256_pin=digest, source_commit='0' * 40)

    def test_single_production_cli_emits_independently_validated_json_yaml(self):
        for case in CASES:
            file, did, tests, _, digest = case
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'out'
                cmd = [sys.executable, '-m', 'scap_ng_tools.converter.direct04',
                    '--schema-root', self.schema, '--source', str(self.source / PREFIX / file),
                    '--sha256', digest, '--oval-definition', 'oval:org.mitre.oval.test:def:' + str(did),
                    '--source-commit', PIN, '--source-path', PREFIX + file, '--output', str(output)]
                proc = subprocess.run(cmd, capture_output=True, text=True)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                doc = json.loads((output / 'assessment.json').read_text())
                self.assertEqual(yaml.safe_load((output / 'assessment.yaml').read_text()), doc)
                validate_native_documents(self.snapshot, {'assessment.json': doc})
                self.assertEqual(len(doc['assessment']['tests']), tests)
                scope = json.loads((output / 'conversion-scope.json').read_text())
                self.assertEqual(scope['conversion_status'], 'CONVERTED_UNVERIFIED')
                self.assertEqual(scope['source_commit'], PIN)
                self.assertEqual(scope['source_definition'], 'oval:org.mitre.oval.test:def:' + str(did))

    def test_cli_revalidates_malformed_standalone_return_before_publication(self):
        case = CASES[0]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'out'
            code = '''
from unittest.mock import patch
from scap_ng_tools.converter import direct04
with patch.object(direct04, 'convert_oval_definition', return_value=({'assessment.json': {'assessment': {}}}, {})):
    direct04.main()
'''
            cmd = [sys.executable, '-c', code, '--schema-root', self.schema,
                   '--source', str(self.source / PREFIX / case[0]), '--sha256', case[4],
                   '--oval-definition', 'oval:org.mitre.oval.test:def:92', '--source-commit', PIN,
                   '--source-path', PREFIX + case[0], '--output', str(output)]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn('JSON Schema', proc.stderr)
            self.assertFalse(output.exists())
