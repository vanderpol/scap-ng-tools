"""Keep one production conversion authority; historical evidence stays readable."""
from pathlib import Path
import tomllib
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
TARGET = 'scap_ng_tools.converter.direct04:main'
SCHEMA_PINS = {'f7e5e845d21e3a38ec5dc5ec04228b763acd9c5b',
               '6012ae25281352a9c2d8a4fde7cb5a4968b4432c'}
FORBIDDEN = ('scap_upconvert_v003', 'scap-ng-research', 'scap_ng_library_cli.py',
             'convert_v04_oval_independent_variable_test.py', 'verify_flat_converter.py',
             '_v04_runtime', 'v04_direct_converter',
             'schema/v0.3', 'schema/v0.2', 'schema/v0.1')


def check_workflow(text):
    for name in FORBIDDEN:
        if name in text:
            raise ValueError('historical production dependency: ' + name)
    workflow = yaml.safe_load(text)
    for job in workflow['jobs'].values():
        for step in job['steps']:
            settings = step.get('with', {})
            if settings.get('repository') == 'vanderpol/scap-ng':
                if settings.get('ref') not in SCHEMA_PINS:
                    raise ValueError('unapproved/floating production schema pin')


class ProductionToolchain(unittest.TestCase):
    def test_single_installed_conversion_entrypoint(self):
        scripts = tomllib.loads((ROOT / 'pyproject.toml').read_text())['project']['scripts']
        conversions = {key: value for key, value in scripts.items()
                       if 'convert' in key or '.converter.' in value}
        self.assertEqual(conversions, {'scapng-convert-v04': TARGET})
        source = (ROOT / 'src/scap_ng_tools/converter/direct04.py').read_text()
        self.assertIn("if __name__ == '__main__':\n    main()", source)

    def test_production_workflows_have_no_obsolete_converter_or_schema(self):
        for path in sorted((ROOT / '.github/workflows').iterdir()):
            if path.suffix not in ('.yml', '.yaml'):
                continue
            with self.subTest(path.name):
                check_workflow(path.read_text())

    def test_guards_reject_historical_routes_and_floating_schema(self):
        baseline = (ROOT / '.github/workflows/flat-schema-contract.yml').read_text()
        for name in FORBIDDEN:
            with self.assertRaisesRegex(ValueError, 'historical'):
                check_workflow(baseline + '\n# ' + name)
        with self.assertRaisesRegex(ValueError, 'schema pin'):
            check_workflow(baseline.replace(next(iter(SCHEMA_PINS & set(baseline.split()))), 'main'))

    def test_current_documentation_digest_matches_frozen_reader(self):
        from scap_ng_tools.contracts.schema_snapshot import FROZEN_DIGEST
        self.assertIn(FROZEN_DIGEST, (ROOT / 'README.md').read_text())
