"""Current canonical bytes, independent generation and the RI handshake."""
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scap_ng_tools.contracts.schema_snapshot_v041 import (
    ASSESSMENT_CLOSURE_SHA256, ASSESSMENT_EXECUTION_FAMILY_SHA256,
    CANONICAL_COMMIT, FLAT_SCHEMA_SHA256, Pinned041SchemaSnapshot,
)
from scap_ng_tools.converter._v04_semantic import PACK_HASH

ROOT = Path(__file__).resolve().parents[1]


class Active041Pins(unittest.TestCase):
    def test_one_manifest_binds_current_schema_pack_and_execution_closure(self):
        pin = json.loads((ROOT / 'canonical-schema-pin.json').read_text())
        self.assertEqual(pin['canonical_sha'], CANONICAL_COMMIT)
        self.assertEqual(pin['schema_family_sha256'], FLAT_SCHEMA_SHA256)
        self.assertEqual(pin['semantic_pack_sha256'], PACK_HASH)
        self.assertEqual(pin['schema_version'], '0.4.1')
        self.assertIs(pin['single_version'], True)
        self.assertEqual(len(pin['files']), 147)
        self.assertEqual(pin['assessment_execution']['family_sha256'], ASSESSMENT_EXECUTION_FAMILY_SHA256)
        self.assertEqual(pin['assessment_execution']['closure_sha256'], ASSESSMENT_CLOSURE_SHA256)
        self.assertEqual(len(pin['assessment_execution']['files']), 8)
        # This independent expected ledger is not regenerated from RI results.
        manifest = ROOT / 'docs/qualification/agnostic-self-assertion/expected-definitions.json'
        self.assertEqual(sha256(manifest.read_bytes()).hexdigest(),
                         '9a9961fc8bcdf30d2d01e9178c0b59befc5e871724c48d6fe38fd9443906ce7c')

    def test_current_canonical_resource_bytes_and_profile_contract(self):
        schema_root = os.environ.get('SCAP_NG_SCHEMA_ROOT')
        if not schema_root:
            self.skipTest('SCAP_NG_SCHEMA_ROOT required for exact source validation')
        snapshot = Pinned041SchemaSnapshot(schema_root)
        pin = json.loads((ROOT / 'canonical-schema-pin.json').read_text())
        for name, expected in pin['files'].items():
            raw = (snapshot.schema_root / name).read_bytes()
            self.assertEqual({'sha256': sha256(raw).hexdigest(), 'bytes': len(raw)}, expected, name)
        from scap_ng_tools.converter.direct04 import conversion_identity
        identity = conversion_identity(snapshot)
        self.assertEqual(identity['schema_family_sha256'], ASSESSMENT_EXECUTION_FAMILY_SHA256)
        self.assertEqual(identity['schema_family_scope'], 'assessment_ref_closure')
        self.assertEqual(identity['flat_schema_family_sha256'], FLAT_SCHEMA_SHA256)
        self.assertNotEqual(identity['schema_family_sha256'], identity['flat_schema_family_sha256'])
        closure = snapshot.assessment_closure()
        self.assertEqual({name: {'sha256': sha256(raw).hexdigest(), 'bytes': len(raw)}
                          for name, raw in closure.items()}, pin['assessment_execution']['files'])
        from jsonschema import Draft202012Validator
        benchmark = json.loads((snapshot.schema_root / 'benchmark.schema.json').read_bytes())
        validator = Draft202012Validator(benchmark['properties']['benchmark']['properties']['profiles'])
        profiles = [{'id': 'baseline', 'disabled_rules': ['a', 'b']},
                    {'id': 'specialized', 'disabled_rules': ['b']}]
        self.assertFalse(list(validator.iter_errors(profiles)))
        profiles[1]['extends'] = 'baseline'
        self.assertTrue(list(validator.iter_errors(profiles)))

    def test_p0_workflow_uses_current_source_and_assessment_closure_pins(self):
        workflow = (ROOT / '.github/workflows/p0-canonical-qualification.yml').read_text()
        self.assertIn('ref: 2d983fcbd7b2367d567ca8ccc689a378d08905e4', workflow)
        self.assertIn('ref: cf99102f13f703b0e5890fd3fd6aab4096eec0cf', workflow)
        self.assertIn('ref: d91e6ba33841e3202dc27d3e0d469a7abd939b16', workflow)
        lane = (ROOT / 'scripts/qualify_p0_041.sh').read_text()
        self.assertIn('cf99102f13f703b0e5890fd3fd6aab4096eec0cf', lane)

    def test_generator_rebuilds_without_reading_previous_semantic_pack(self):
        schema = os.environ.get('SCAP_NG_SCHEMA_ROOT')
        oval = os.environ.get('SCAP_NG_OVAL_ROOT')
        if not schema or not oval:
            self.skipTest('exact canonical and official OVAL checkouts required')
        with tempfile.TemporaryDirectory() as temp:
            outputs = [Path(temp) / 'one.json', Path(temp) / 'two.json']
            for output in outputs:
                command = [sys.executable, '-c',
                           'import runpy; from unittest.mock import patch; '
                           'p=patch("scap_ng_tools.converter._v04_semantic.contracts", '
                           'side_effect=AssertionError("previous pack read during generation")); '
                           'p.start(); runpy.run_path("scripts/generate_v04_semantic_pack.py", run_name="__main__")',
                           '--schema-root', schema, '--oval-root', oval, '--output', str(output)]
                result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(outputs[0].read_bytes(), outputs[1].read_bytes())
            self.assertEqual(sha256(outputs[0].read_bytes()).hexdigest(), PACK_HASH)


if __name__ == '__main__':
    unittest.main()
