"""Contract: standalone OVAL and XCCDF Rules share one production visitor."""
import inspect
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from scripts.convert_self_assertion_corpus import source_documents

from scap_ng_tools.converter import direct04, oval_platform, oval_variables
from scap_ng_tools.converter.conversion_budget import ConversionBudget, ConversionBudgetExceeded




class FullSourceCorpusInputTests(unittest.TestCase):
    def test_embedded_oval_is_included_without_environment_opt_in(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "SCAP_1.4" / "OVAL_Test_Content"
            agnostic = root / "agnostic"
            agnostic.mkdir(parents=True)
            (agnostic / "standalone.xml").write_bytes(b"standalone")
            with ZipFile(agnostic / "oval-def-ext.zip", "w") as archive:
                archive.writestr("oval-def-ext.xml", b"embedded")
            with patch.dict(os.environ, {}, clear=True):
                records = list(source_documents(Path(temp), ("agnostic",)))
            self.assertEqual([str(row[0]) for row in records], [
                "SCAP_1.4/OVAL_Test_Content/agnostic/standalone.xml",
                "SCAP_1.4/OVAL_Test_Content/agnostic/oval-def-ext.zip!oval-def-ext.xml",
            ])
            self.assertEqual([row[2] for row in records], [b"standalone", b"embedded"])

    def test_missing_embedded_oval_is_not_silently_omitted(self):
        with tempfile.TemporaryDirectory() as temp:
            agnostic = Path(temp) / "SCAP_1.4" / "OVAL_Test_Content" / "agnostic"
            agnostic.mkdir(parents=True)
            (agnostic / "standalone.xml").write_bytes(b"standalone")
            with self.assertRaises(FileNotFoundError):
                list(source_documents(Path(temp), ("agnostic",)))


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



class StandaloneSourceCompatibilityTests(unittest.TestCase):
    @staticmethod
    def source(version='5.11'):
        xml = """<oval:oval_definitions
            xmlns:oval="http://oval.mitre.org/XMLSchema/oval-definitions-5"
            xmlns:oval-common="http://oval.mitre.org/XMLSchema/oval-common-5"
            xmlns:ind="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
          <oval:generator><oval-common:schema_version>VERSION</oval-common:schema_version></oval:generator>
          <oval:definitions><oval:definition id="def-a"/></oval:definitions>
          <oval:tests>
            <ind:variable_test id="test-a"><ind:object object_ref="obj-root"/></ind:variable_test>
          </oval:tests>
          <oval:objects>
            <ind:variable_object id="obj-root">
              <oval:set><oval:object_reference>obj-leaf</oval:object_reference></oval:set>
            </ind:variable_object>
            <ind:variable_object id="obj-leaf">
              <ind:var_ref>var-source</ind:var_ref>
              <oval:filter action="include">state-match</oval:filter>
            </ind:variable_object>
          </oval:objects>
          <oval:states><ind:variable_state id="state-match">
            <ind:value var_ref="var-state"/>
          </ind:variable_state></oval:states>
          <oval:variables>
            <oval:constant_variable id="var-source"><oval:value>ok</oval:value></oval:constant_variable>
            <oval:constant_variable id="var-state"><oval:value>ok</oval:value></oval:constant_variable>
          </oval:variables>
        </oval:oval_definitions>"""
        return xml.replace('VERSION', version).encode('utf-8')

    def test_older_publisher_oval_versions_admitted_without_rewriting(self):
        for version in ('5.11', '5.11.1', '5.11.2', '5.12.2', '5.12.3'):
            with self.subTest(version=version):
                src = oval_platform.StandalonePlatformSource(self.source(version), 'pinned-original.xml')
                self.assertEqual(src.oval_schema_version, version)

    def test_unknown_oval_source_version_rejected(self):
        for version in ('', '5.10', '5.13', 'not-an-oval-version'):
            with self.subTest(version=version):
                with self.assertRaisesRegex(direct04.QualifiedConversionError,
                                            'unsupported standalone source OVAL version'):
                    oval_platform.StandalonePlatformSource(self.source(version), 'x.xml')

    def test_recursive_set_filter_and_variable_references_are_counted(self):
        src = oval_platform.StandalonePlatformSource(self.source(), 'x.xml')
        uses = src.object_uses('x.xml', 'test-a', 'test')
        self.assertEqual(uses['obj-root'], 1)
        self.assertEqual(uses['obj-leaf'], 1)
        self.assertEqual(set(uses), {'obj-root', 'obj-leaf'})

    def test_provenance_retains_text_backed_set_filter_variable_references(self):
        src = oval_platform.StandalonePlatformSource(self.source(), 'x.xml')
        root = src.node('x.xml', 'obj-root', 'object')
        leaf = src.node('x.xml', 'obj-leaf', 'object')
        self.assertIn({'attribute': 'object_reference_text', 'id': 'obj-leaf'},
                      oval_platform.references(root))
        self.assertIn({'attribute': 'filter_text', 'id': 'state-match'},
                      oval_platform.references(leaf))
        self.assertIn({'attribute': 'var_ref_text', 'id': 'var-source'},
                      oval_platform.references(leaf))

    def test_deep_acyclic_set_chain_is_stack_safe(self):
        # Former 0.3 worklist test: do not turn a valid deep graph into a
        # converter exception merely because Python recursion is bounded.
        depth = 1500
        objects = []
        for index in range(depth):
            following = ('obj-chain-' + str(index + 1)
                         if index + 1 < depth else 'obj-leaf')
            objects.append(
                '<ind:variable_object id="obj-chain-' + str(index) + '">'
                '<oval:set><oval:object_reference>' + following +
                '</oval:object_reference></oval:set></ind:variable_object>')
        payload = self.source().replace(
            b'obj-leaf</oval:object_reference>',
            b'obj-chain-0</oval:object_reference>', 1)
        payload = payload.replace(
            b'</oval:objects>', ''.join(objects).encode() + b'</oval:objects>')
        original = oval_platform.StandalonePlatformSource(payload, 'deep.xml')
        uses = original.object_uses('deep.xml', 'test-a', 'test')
        self.assertEqual(uses['obj-root'], 1)
        self.assertEqual(uses['obj-leaf'], 1)
        self.assertEqual(sum(uses.values()), depth + 2)

    def test_deep_graph_cycle_is_rejected_without_recursion_error(self):
        depth = 1250
        objects = []
        for index in range(depth):
            following = ('obj-chain-' + str(index + 1)
                         if index + 1 < depth else 'obj-chain-0')
            objects.append(
                '<ind:variable_object id="obj-chain-' + str(index) + '">'
                '<oval:set><oval:object_reference>' + following +
                '</oval:object_reference></oval:set></ind:variable_object>')
        payload = self.source().replace(
            b'obj-leaf</oval:object_reference>',
            b'obj-chain-0</oval:object_reference>', 1)
        payload = payload.replace(
            b'</oval:objects>', ''.join(objects).encode() + b'</oval:objects>')
        original = oval_platform.StandalonePlatformSource(payload, 'cycle.xml')
        with self.assertRaisesRegex(direct04.QualifiedConversionError,
                                    'cyclic standalone OVAL dependency'):
            original.object_uses('cycle.xml', 'test-a', 'test')

    def test_original_0_3_dependency_node_budget_is_fail_closed(self):
        source = oval_platform.StandalonePlatformSource(self.source(), 'budget.xml')
        with patch.object(oval_platform.StandalonePlatformSource,
                          'DEFAULT_DEPENDENCY_BUDGET',
                          ConversionBudget(dependency_nodes=2)):
            with self.assertRaisesRegex(
                    ConversionBudgetExceeded,
                    'conversion_resource_limit:dependency_nodes'):
                source.object_uses('budget.xml', 'test-a', 'test')

    def test_original_0_3_dependency_edge_budget_is_fail_closed(self):
        source = oval_platform.StandalonePlatformSource(self.source(), 'budget.xml')
        with patch.object(oval_platform.StandalonePlatformSource,
                          'DEFAULT_DEPENDENCY_BUDGET',
                          ConversionBudget(dependency_edges=1)):
            with self.assertRaisesRegex(
                    ConversionBudgetExceeded,
                    'conversion_resource_limit:dependency_edges'):
                source.object_uses('budget.xml', 'test-a', 'test')

    def test_filter_hidden_missing_variable_is_fatal(self):
        payload = self.source().replace(b'var_ref="var-state"', b'var_ref="unknown-variable"')
        original = oval_platform.StandalonePlatformSource(payload, 'filter.xml')
        with self.assertRaisesRegex(direct04.QualifiedConversionError,
                                    'unresolved variable'):
            original.object_uses('filter.xml', 'test-a', 'test')

    def test_shared_object_edges_preserve_ref_counts(self):
        payload = self.source().replace(
            b'</oval:set>', b'<oval:object_reference>obj-leaf</oval:object_reference></oval:set>', 1)
        original = oval_platform.StandalonePlatformSource(payload, 'shared.xml')
        uses = original.object_uses('shared.xml', 'test-a', 'test')
        self.assertEqual(uses['obj-leaf'], 2)
        self.assertEqual(uses['obj-root'], 1)

    def test_missing_filter_state_is_not_silently_skipped(self):
        data = self.source().replace(b'state-match</oval:filter>',
                                     b'unknown-state</oval:filter>')
        src = oval_platform.StandalonePlatformSource(data, 'x.xml')
        with self.assertRaisesRegex(direct04.QualifiedConversionError, 'unresolved state'):
            src.object_uses('x.xml', 'test-a', 'test')

    def test_missing_set_object_is_not_silently_skipped(self):
        data = self.source().replace(b'obj-leaf</oval:object_reference>',
                                     b'unknown-object</oval:object_reference>')
        src = oval_platform.StandalonePlatformSource(data, 'x.xml')
        with self.assertRaisesRegex(direct04.QualifiedConversionError, 'unresolved object'):
            src.object_uses('x.xml', 'test-a', 'test')

    def test_object_set_cycle_fails_closed(self):
        data = self.source().replace(b'var-source</ind:var_ref>',
                                     b'var-source</ind:var_ref><oval:set><oval:object_reference>obj-root</oval:object_reference></oval:set>')
        src = oval_platform.StandalonePlatformSource(data, 'x.xml')
        with self.assertRaisesRegex(direct04.QualifiedConversionError, 'cyclic standalone OVAL dependency'):
            src.object_uses('x.xml', 'test-a', 'test')


if __name__ == '__main__':
    unittest.main()
