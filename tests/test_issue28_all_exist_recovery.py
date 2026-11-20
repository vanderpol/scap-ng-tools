"""Native 0.4 all_exist lowering tests for Issue #28."""
from hashlib import sha256
import json
import os
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

from scap_ng_tools.converter.direct04 import load_runtime

RECOVERY_REPORT = Path(__file__).resolve().parents[1] / 'docs/evidence/issue28/NATIVE-EXISTENCE-RECOVERY.json'
INPUT_RECOVERY_REPORT = Path(__file__).resolve().parents[1] / 'docs/evidence/issue28/NATIVE-INPUT-RECOVERY.json'


class NativeExistenceLowering(unittest.TestCase):
    def test_all_65_recovery_delta_has_no_regressions(self):
        report = json.loads(RECOVERY_REPORT.read_text(encoding='utf-8'))
        self.assertEqual(report['candidate']['converted'], 6240)
        self.assertEqual(report['candidate']['blocked'], 2652)
        self.assertEqual(report['delta'], {
            'all_recovered_primary_all_exist': True,
            'recovered': 1716,
            'regressions': 0,
        })
        self.assertEqual(sum(item['recovered'] for item in report['benchmarks'].values()), 1716)

    def test_native_input_recovery_delta_is_reconciled(self):
        report = json.loads(INPUT_RECOVERY_REPORT.read_text(encoding='utf-8'))
        self.assertEqual(report['candidate']['converted'], 6531)
        self.assertEqual(report['candidate']['blocked'], 2361)
        self.assertEqual(report['delta']['recovered'], 2007)
        self.assertEqual(report['delta']['regressions'], 0)
        self.assertEqual(report['delta']['check_import_export_recovered'], 291)
        self.assertEqual(sum(item['recovered'] for item in report['benchmarks'].values()), 2007)
        self.assertEqual(report['remaining_primary_blockers'][0]['rules'], 1653)

    def test_production_converter_admits_all_exist_as_native_representability(self):
        # This is a source-to-native representability witness.  It deliberately
        # uses the production visitor with native_recovery disabled; the
        # resulting one_or_more cardinality is not an independent OVAL runtime
        # equivalence claim.
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_converter import AssessmentConverter
        from v04_direct_scap_source import OVAL

        namespace = OVAL + '#unix'
        object_node = ET.fromstring(
            f'<file_object xmlns="{namespace}" id="obj-all"/>')
        test_node = ET.fromstring(
            f'<file_test xmlns="{namespace}" id="tst-all" '
            'check_existence="all_exist" check="all">'
            '<object object_ref="obj-all"/></file_test>')

        class Source:
            nodes = {'component': {'obj-all': object_node}}
            def object_uses(self, _component, _identifier, _kind):
                return {_identifier: 1}
            def node(self, component, identifier, _kind):
                return self.nodes[component][identifier]

        mapping = {
            'capability': 'unix.file',
            'source': {'namespace': namespace, 'test': 'file_test',
                       'object': 'file_object', 'state': 'file_state'},
            'native': {'test_source': {'kind': 'object'}, 'selector_map': {}},
        }
        visitor = AssessmentConverter(Source(), 'component', [mapping],
                                      native_recovery=False)
        native = visitor.convert_test(test_node)
        test = visitor.tests[native['test']]
        self.assertEqual(test['require']['item_requirement']['items_found'],
                         'one_or_more')

    def test_none_exist_drops_state_graph_in_all_conversion_modes(self):
        # OVAL evaluates Test existence before State matching.  The native
        # absence requirement must therefore not pull a State dependency into
        # either normal or recovery conversion; recovery is not a semantic
        # switch.  The source State reference remains in the warning trace.
        import xml.etree.ElementTree as ET
        from scap_ng_tools.converter.direct04 import load_runtime
        load_runtime()
        from v04_direct_converter import AssessmentConverter
        from v04_direct_scap_source import OVAL

        namespace = OVAL + '#unix'
        object_node = ET.fromstring(
            f'<file_object xmlns="{namespace}" id="obj-none"/>')
        test_node = ET.fromstring(
            f'<file_test xmlns="{namespace}" id="tst-none" '
            'check_existence="none_exist" check="all">'
            '<object object_ref="obj-none"/>'
            '<state state_ref="st-never-needed"/>'
            '</file_test>')

        class Source:
            nodes = {'component': {'obj-none': object_node}}

            def node(self, component, identifier, _kind):
                return self.nodes[component][identifier]

            def object_uses(self, _component, _identifier, _kind):
                return {}

        mapping = {
            'capability': 'unix.file',
            'source': {'namespace': namespace, 'test': 'file_test',
                       'object': 'file_object', 'state': 'file_state'},
            'native': {'test_source': {'kind': 'object'}, 'selector_map': {}},
        }
        for native_recovery in (False, True):
            with self.subTest(native_recovery=native_recovery):
                visitor = AssessmentConverter(Source(), 'component', [mapping],
                                              native_recovery=native_recovery)
                visitor.reference = lambda identifier, kind: (
                    (_ for _ in ()).throw(AssertionError(
                        f'unexpected {kind} reference {identifier}'))
                    if kind == 'state' else {'capability': 'unix.file'})
                visitor.same_family = lambda *_args: None
                result = visitor.convert_test(test_node)
                test = visitor.tests[result['test']]
                self.assertEqual(test['require']['item_requirement']['items_found'], 'none')
                self.assertNotIn('items_satisfying', test['require'])
                warning = next(item for item in visitor.conversion_warnings
                               if item['code'] == 'oval_test_absence_controls_ignored')
                self.assertEqual(warning['source_state_refs'], ['st-never-needed'])

    def test_native_04_existence_mapping_boundaries(self):
        native_items_found = load_runtime().native_items_found
        self.assertEqual(native_items_found('all_exist'), 'one_or_more')
        self.assertEqual(native_items_found('at_least_one_exists'), 'one_or_more')
        self.assertEqual(native_items_found('none_exist'), 'none')
        self.assertEqual(native_items_found('only_one_exists'), 'exactly_one')
        self.assertEqual(native_items_found('any_exist'), 'zero_or_more')
        with self.assertRaisesRegex(ValueError, 'unsupported Test existence'):
            native_items_found('unknown_existence')

    def test_source_backed_rule_emits_native_one_or_more_and_provenance(self):
        source_dir = os.environ.get('SCAP_NG_ISSUE28_SOURCE_DIR')
        schema_root = os.environ.get('SCAP_NG_SCHEMA_ROOT')
        if not source_dir or not schema_root:
            self.skipTest('Issue #28 source and schema fixtures are required')
        source = Path(source_dir) / 'U_Adobe_Acrobat_Pro_DC_Continuous_V2R2_STIG_SCAP_1-4_Benchmark-enhancedV2-signed.zip'
        if not source.is_file():
            self.skipTest('Adobe source fixture is not available')
        from scap_ng_tools.converter.direct04 import convert_benchmark
        source_hash = sha256(source.read_bytes()).hexdigest()
        documents, trace, coverage = convert_benchmark(
            schema_root=schema_root, source=source, sha256_pin=source_hash,
            native_recovery=True)
        source_rule = 'xccdf_mil.disa.stig_rule_SV-213126r766535_rule'
        row = next(row for row in coverage['rules'] if row['source_rule'] == source_rule)
        self.assertEqual(row['status'], 'converted')
        binding = next(item for item in trace['rules'] if item['source_rule'] == source_rule)
        controls = binding['source_test_controls']
        self.assertTrue(controls)
        self.assertTrue(all(item['native_items_found'] == 'one_or_more' for item in controls))
        assessment = next(document['assessment'] for path, document in documents.items()
                          if path.endswith('.json') and 'assessments/' in path)
        self.assertTrue(any(test['require']['item_requirement']['items_found'] == 'one_or_more'
                            for test in assessment['tests'].values()))

    def test_source_backed_check_export_becomes_native_input_parameter(self):
        source_dir = os.environ.get('SCAP_NG_ISSUE28_SOURCE_DIR')
        schema_root = os.environ.get('SCAP_NG_SCHEMA_ROOT')
        if not source_dir or not schema_root:
            self.skipTest('Issue #28 source and schema fixtures are required')
        source = Path(source_dir) / 'U_MS_IE11_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip'
        if not source.is_file():
            self.skipTest('IE11 source fixture is not available')
        from scap_ng_tools.converter.direct04 import convert_benchmark
        source_hash = sha256(source.read_bytes()).hexdigest()
        documents, trace, coverage = convert_benchmark(
            schema_root=schema_root, source=source, sha256_pin=source_hash,
            native_recovery=True)
        source_rule = 'xccdf_mil.disa.fso_rule_SV-223017r961089_rule'
        row = next(row for row in coverage['rules'] if row['source_rule'] == source_rule)
        self.assertEqual(row['status'], 'converted')
        binding = next(item for item in trace['rules'] if item['source_rule'] == source_rule)
        self.assertTrue(binding['policy_parameters'])
        self.assertEqual(binding['conversion_warnings'][0]['code'], 'native_input_binding_unproved')
        assessment = next(document['assessment'] for path, document in documents.items()
                          if path.endswith('.json') and 'assessments/' in path
                          and document['assessment']['id'] == binding['assessment'])
        self.assertTrue(assessment['inputs'])


if __name__ == '__main__':
    unittest.main()
