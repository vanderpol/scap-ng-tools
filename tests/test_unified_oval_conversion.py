"""Contract: standalone OVAL and XCCDF Rules share one production visitor."""
import inspect
import unittest
from unittest.mock import patch

from scap_ng_tools.converter import direct04, oval_platform, oval_variables


class UnifiedOvalConverterTests(unittest.TestCase):
    def test_standalone_route_never_filters_by_test_type(self):
        sentinel = ({'assessment.json': {'assessment': {'id': 'fixture'}}},
                    {'source_path': 'SCAP_1.4/OVAL_Test_Content/agnostic/fixture.xml'})
        with patch.object(oval_platform, 'convert_definition', return_value=sentinel) as convert:
            self.assertIs(
                direct04.convert_oval_definition(
                    schema_root='schema', source='source.xml',
                    sha256_pin='pinned-sha', definition_id='def-1',
                    source_commit='source-commit', source_path='source-path'),
                sentinel)
            convert.assert_called_once_with(
                schema_root='schema', source='source.xml',
                sha256_pin='pinned-sha', definition_id='def-1',
                source_commit='source-commit', source_path='source-path')

    def test_legacy_variable_adapter_is_alias_not_duplicate_visitor(self):
        self.assertIs(oval_variables.convert_definition, oval_platform.convert_definition)
        self.assertIs(oval_variables.OvalSource, oval_platform.StandalonePlatformSource)

    def test_standalone_and_benchmark_use_production_visitor(self):
        engine = direct04.load_runtime()
        signature = inspect.signature(engine.AssessmentConverter)
        self.assertIn('native_recovery', signature.parameters)
        self.assertFalse(signature.parameters['native_recovery'].default)
        self.assertNotIn('preserve_variable_references', signature.parameters)

    def test_standalone_adapter_has_no_capability_allowlist(self):
        source = inspect.getsource(oval_platform.convert_definition)
        self.assertIn('engine.AssessmentConverter(', source)
        self.assertIn('native_recovery=True', source)
        self.assertNotIn('SUPPORTED_TESTS', source)
        self.assertNotIn('unsupported = sorted(', source)


if __name__ == '__main__':
    unittest.main()
