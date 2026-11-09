"""Final API/artifact boundaries fail closed even if an internal gate regresses."""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scap_ng_tools.contracts import FrozenSchemaSnapshot
from scap_ng_tools.converter import direct04


def valid_document():
    return {'assessment': {
        'id': 'validation-boundary-assessment', 'version': 1,
        'assessment_title': 'Supplied data validation fixture', 'mode': 'automated',
        'class': 'compliance', 'specification': {'id': 'scap-ng.pre-alpha.assessment', 'version': '0.4.0'},
        'tests': {'validation-boundary-test': {
            'test_title': 'Read-only selector data', 'capability': 'unix.file',
            'object': {'filepath': {'equals': '/etc/passwd'}}, 'reported_elements': 'all',
            'require': {'item_requirement': {'items_found': 'one_or_more', 'items_satisfying': 'every'},
                'field_requirement': {'values_found': 'one_or_more', 'values_matching': 'every'},
                'fields': {'owner_uid': {'datatype': 'integer', 'equals': 0}}}}},
        'evaluate': {'test': 'validation-boundary-test'}}}


class ConversionValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = os.environ.get('SCAP_NG_SCHEMA_ROOT')
        if not cls.root:
            raise unittest.SkipTest('SCAP_NG_SCHEMA_ROOT required for approved-schema assertions')
        cls.snapshot = FrozenSchemaSnapshot(cls.root)
        cls.engine = direct04.load_runtime()

    def test_obsolete_require_and_malformed_output_are_rejected(self):
        for corrupt in ('obsolete', 'missing_version'):
            doc = valid_document()
            if corrupt == 'obsolete':
                q = doc['assessment']['tests']['validation-boundary-test']['require']
                q.update(q.pop('item_requirement'))
            else:
                del doc['assessment']['version']
            with self.subTest(corrupt), self.assertRaisesRegex(ValueError, 'JSON Schema'):
                direct04.validate_native_documents(self.snapshot, {'assessment.json': doc})

    def test_provenance_fingerprints_actual_loaded_package(self):
        from scap_ng_tools.contracts.schema_snapshot import FROZEN_DIGEST
        identity = direct04.conversion_identity(self.snapshot)
        self.assertEqual(identity['schema_family_sha256'], FROZEN_DIGEST)
        self.assertNotEqual(identity['converter_source_sha256'], sha256(b'').hexdigest())
        self.assertEqual(len(identity['converter_commit']), 40)

    def test_final_focused_and_benchmark_apis_refuse_invalid_returned_set(self):
        doc = valid_document()
        del doc['assessment']['assessment_title']
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'in.zip'
            source.write_bytes(b'controlled API fault injection')
            args = dict(schema_root=self.root, source=source, sha256_pin=sha256(source.read_bytes()).hexdigest())
            with patch('v04_direct_scap_source.SourceModel', return_value=object()):
                with patch.object(self.engine, 'convert', return_value=({'a.json': doc}, {})):
                    with self.assertRaisesRegex(ValueError, 'JSON Schema'):
                        direct04.convert_focused(**args, rule_ids=['original-rule'])
                with patch.object(self.engine, 'convert_benchmark', return_value=(
                        {'a.json': doc}, {}, {'mode': 'automatic', 'rules': [{'proof_level': 'authoring_validated'}]})):
                    with self.assertRaisesRegex(ValueError, 'JSON Schema'):
                        direct04.convert_benchmark(**args)

    def test_actual_rendered_payloads_are_validated_and_match(self):
        docs = {'assessment.json': valid_document()}
        rendered = direct04.render_native_documents(self.snapshot, docs)
        import yaml
        self.assertEqual(json.loads(rendered['assessment.json'][0]), docs['assessment.json'])
        self.assertEqual(yaml.safe_load(rendered['assessment.json'][1]), docs['assessment.json'])
        for text in ('assessment: {}', 'assessment: [', 'assessment: null',
                     'assessment: {}\n' + yaml.safe_dump(docs['assessment.json'])):
            with patch('v04_direct_yaml.authoring_yaml', return_value=text):
                with self.assertRaises(ValueError):
                    direct04.render_native_documents(self.snapshot, docs)
        # Even another schema-valid document cannot replace the evaluated AST.
        changed = deepcopy(docs['assessment.json'])
        changed['assessment']['assessment_title'] = 'Changed by a renderer'
        with patch('v04_direct_yaml.authoring_yaml', return_value=yaml.safe_dump(changed)):
            with self.assertRaisesRegex(ValueError, 'differs'):
                direct04.render_native_documents(self.snapshot, docs)

    def test_cli_serialization_failure_exits_nonzero_before_publishing(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / 'in.zip', Path(directory) / 'out'
            source.write_bytes(b'CLI publication boundary fault injection')
            code = '''
import sys
from unittest.mock import patch
from scap_ng_tools.converter import direct04
direct04.load_runtime()
from test_conversion_validation import valid_document
with patch('v04_direct_yaml.authoring_yaml', return_value='assessment: {}'), \\
     patch.object(direct04, 'convert_focused', return_value=({'a.json': valid_document()}, {})):
    direct04.main()
'''
            command = [sys.executable, '-c', code, '--schema-root', self.root,
                       '--source', str(source), '--sha256', sha256(source.read_bytes()).hexdigest(),
                       '--rule', 'original-rule', '--output', str(output)]
            env = dict(os.environ, PYTHONPATH=os.pathsep.join(['src', 'tests']))
            proc = subprocess.run(command, capture_output=True, text=True, env=env)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn('serialized native output', proc.stderr)
            self.assertFalse(output.exists())
