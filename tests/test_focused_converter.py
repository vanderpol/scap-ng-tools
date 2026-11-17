"""Current focused converter has a portable, fail-closed 0.4 CLI surface."""

from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scap_ng_tools.converter import convert_focused


ZIP_SHA = '2f46264b5fa21c8a033236121794ebe372314bf7458dac0aca4f81179fe7ece0'
# Owner-approved 0.4 re-freeze: Item counts are nested under item_requirement.
# The old baseline remains available in Git history; no semantic proof is claimed.
NATIVE_SHA = '006d50d0cf84ef48bac6594f5286a74fe3fcbfd770a8c8558cf385896a2c1bd6'
RULES = [
    'xccdf_mil.disa.stig_rule_SV-278139r1182083_rule',
    'xccdf_mil.disa.stig_rule_SV-278080r1180946_rule',
]


class FocusedConverterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schema = os.environ.get('SCAP_NG_SCHEMA_ROOT')
        fixture = os.environ.get('SCAP_NG_SOURCE_FIXTURE')
        if not schema or not fixture:
            raise unittest.SkipTest('Set explicit SCAP_NG_SCHEMA_ROOT and SCAP_NG_SOURCE_FIXTURE')
        cls.schema = Path(schema)
        cls.fixture = Path(fixture)

    def test_pinned_source_produces_exact_native_output_without_research_modules(self):
        documents, trace = convert_focused(
            schema_root=self.schema, source=self.fixture,
            sha256_pin=ZIP_SHA, rule_ids=RULES)
        self.assertEqual(len(documents), 8)
        self.assertTrue(trace)
        payload = json.dumps(documents, sort_keys=True).encode('utf-8')
        self.assertEqual(sha256(payload).hexdigest(), NATIVE_SHA)

    def test_cli_writes_structurally_valid_review_artifacts(self):
        with tempfile.TemporaryDirectory(prefix='scapng-converter-cli-') as temp:
            output = Path(temp) / 'converted'
            command = [sys.executable, '-m', 'scap_ng_tools.converter.direct04',
                       '--schema-root', str(self.schema), str(self.fixture),
                       '--sha256', ZIP_SHA, '--output', str(output)]
            for rule in RULES:
                command.extend(['--rule', rule])
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(list(output.rglob('*.yaml'))), 8)
            self.assertEqual(len(list(output.rglob('*.json'))), 10)
            scope = json.loads((output / 'conversion-scope.json').read_text())
            self.assertEqual(scope['conversion_status'], 'CONVERTED_UNVERIFIED')
            self.assertFalse(scope['independent_semantic_proof'])
            self.assertFalse(scope['scanner_execution'])
            self.assertEqual(scope['compile_and_verify_modes'], 'not_migrated')

    def test_unmigrated_proof_flag_fails_without_creating_output(self):
        with tempfile.TemporaryDirectory(prefix='scapng-converter-gate-') as temp:
            output = Path(temp) / 'not-created'
            command = [sys.executable, '-m', 'scap_ng_tools.converter.direct04',
                       '--schema-root', str(self.schema), str(self.fixture),
                       '--sha256', ZIP_SHA, '--rule', RULES[0],
                       '--output', str(output), '--verify']
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('require separate owner-qualified ports', result.stderr)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
