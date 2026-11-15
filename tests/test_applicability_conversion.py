import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET
from types import SimpleNamespace
from unittest.mock import patch

from scripts.publish_issue28_assessments import verify_published_inventory
from scap_ng_tools.converter.applicability import (
    _make_composite, build_applicability, extract_platform_specifications, inherited_platform_refs,
)

FIXTURES = Path(__file__).parent / 'fixtures' / 'applicability'
XCCDF = 'http://checklists.nist.gov/xccdf/1.2'
CPE = 'http://cpe.mitre.org/language/2.0'
OVAL = 'http://oval.mitre.org/XMLSchema/oval-definitions-5'


class ApplicabilityConversionTests(unittest.TestCase):
    def test_linux_and_windows_logical_trees_are_preserved(self):
        for name, platform_id, operator, negate, fact_count in (
            ('linux-platform.xml', 'fixture-linux-platform', 'AND', False, 3),
            ('windows-platform.xml', 'fixture-windows-platform', 'AND', True, 1),
        ):
            root = ET.parse(FIXTURES / name).getroot()
            specs = extract_platform_specifications(SimpleNamespace(root=root))
            logical = specs[platform_id]['logical_tests'][0]
            self.assertEqual(logical['operator'], operator)
            self.assertEqual(logical['negate'] == 'true', negate)
            self.assertEqual(len(logical['facts']) + sum(len(c['facts']) for c in logical['children']), fact_count)
            if fact_count == 3:
                self.assertEqual(logical['children'][0]['operator'], 'OR')
            self.assertTrue(logical['facts'][0]['source_xml_sha256'])

    def test_boolean_wrapper_is_deduplicated_and_retains_negation(self):
        shared, traces = {}, {}
        first = _make_composite('Linux', 'fixture-linux-platform', ['fact-a', 'fact-b'], 'OR', 'true', shared, traces)
        second = _make_composite('Linux', 'fixture-linux-platform', ['fact-a', 'fact-b'], 'OR', 'true', shared, traces)
        self.assertEqual(first, second)
        self.assertEqual(len(shared), 1)
        expression = next(iter(shared.values()))['assessment']['evaluate']
        self.assertEqual(expression, {'not': {'or': [{'assessment': 'fact-a'}, {'assessment': 'fact-b'}]}})
        self.assertEqual(shared[first]['assessment']['dependencies']['condition-0']['purpose'], 'applicability')


    def test_boolean_states_and_all_native_operators_are_retained_structurally(self):
        # These labels stand for independently produced PASS, FAIL, ERROR,
        # UNKNOWN, and NOT_EVALUATED Assessments. This test deliberately does
        # not execute them or assert scanner/runtime equivalence.
        state_ids = ['pass-assessment', 'fail-assessment', 'error-assessment',
                     'unknown-assessment', 'not-evaluated-assessment']
        for operator in ('AND', 'OR', 'ONE', 'XOR'):
            shared, traces = {}, {}
            aid = _make_composite('state vector', 'fixture-state-vector',
                                  state_ids[:3], operator, 'false', shared, traces)
            expression = shared[aid]['assessment']['evaluate']
            self.assertIn(operator.lower(), expression)
            self.assertEqual([x['assessment'] for x in expression[operator.lower()]], state_ids[:3])
        shared, traces = {}, {}
        inner = _make_composite('inner', 'fixture-inner', state_ids[:2], 'AND', 'false', shared, traces)
        outer = _make_composite('outer', 'fixture-outer', [inner, state_ids[4]], 'OR', 'true', shared, traces)
        self.assertEqual(shared[outer]['assessment']['evaluate'], {
            'not': {'or': [{'assessment': inner}, {'assessment': state_ids[4]}]}})

    def test_xccdf_inheritance_preserves_rule_group_benchmark_order(self):
        benchmark = ET.Element(f'{{{XCCDF}}}Benchmark')
        ET.SubElement(benchmark, f'{{{XCCDF}}}platform', {'idref': 'cpe:/o:fixture:benchmark'})
        group = ET.SubElement(benchmark, f'{{{XCCDF}}}Group')
        ET.SubElement(group, f'{{{XCCDF}}}platform', {'idref': '#fixture-linux-platform'})
        rule = ET.SubElement(group, f'{{{XCCDF}}}Rule', {'id': 'fixture-inherited-rule'})
        ET.SubElement(rule, f'{{{XCCDF}}}platform', {'idref': 'cpe:/a:fixture:rule'})
        source = SimpleNamespace(benchmark=benchmark, parents={group: benchmark, rule: group})
        self.assertEqual(inherited_platform_refs(source, rule), [
            'cpe:/a:fixture:rule', '#fixture-linux-platform', 'cpe:/o:fixture:benchmark'])

    def test_duplicate_source_and_generated_id_collisions_fail_closed(self):
        first = ET.parse(FIXTURES / 'linux-platform.xml').getroot()
        second = ET.parse(FIXTURES / 'linux-platform.xml').getroot()
        second.find(f'{{{CPE}}}title').text = 'Conflicting Linux meaning'
        root = ET.Element('root'); root.extend([first, second])
        with self.assertRaisesRegex(ValueError, 'conflicting duplicate CPE platform ID'):
            extract_platform_specifications(SimpleNamespace(root=root))
        shared, traces = {}, {}
        with patch('scap_ng_tools.converter.applicability._slug', return_value='platform-collision-assessment'):
            _make_composite('one', 'identity-one', ['a', 'b'], 'AND', 'false', shared, traces)
            with self.assertRaisesRegex(ValueError, 'conflicting generated Assessment identity'):
                _make_composite('two', 'identity-two', ['a', 'c'], 'OR', 'false', shared, traces)


    def test_publication_graph_rejects_unresolved_dependencies_and_cycles(self):
        base = {
            'documents/pkg/authoring/direct-slice/assessments/a.json': {
                'assessment': {'id': 'a-assessment', 'version': 1, 'assessment_title': 'a',
                               'mode': 'automated', 'class': 'compliance', 'tests': {},
                               'dependencies': {'child': {'assessment': 'b-assessment', 'expected_version': 1}},
                               'evaluate': {'assessment': 'b-assessment'}}},
            'documents/pkg/authoring/direct-slice/assessments/b.json': {
                'assessment': {'id': 'b-assessment', 'version': 1, 'assessment_title': 'b',
                               'mode': 'automated', 'class': 'compliance', 'tests': {},
                               'evaluate': {'not_evaluated': {'reason': 'fixture'}}}},
            'documents/pkg/authoring/direct-slice/applicability.json': {
                'applicability': {'id': 'catalog', 'conditions': {
                    'condition-a': {'assessment': 'a-assessment'}}}},
            'documents/pkg/authoring/direct-slice/benchmark.json': {
                'benchmark': {'platform': {'applicability': {'conditions': ['condition-a']}}}},
            'documents/pkg/authoring/direct-slice/rules/rule.json': {
                'rule': {'applicability': ['condition-a'],
                         'assessment_choices': {'default': {'assessment': 'a-assessment'}}}},
        }
        report = verify_published_inventory(base)
        self.assertEqual(report['packages'], 1)
        cyclic = dict(base)
        cyclic['documents/pkg/authoring/direct-slice/assessments/b.json'] = {
            'assessment': {'id': 'b-assessment', 'version': 1, 'assessment_title': 'b',
                           'mode': 'automated', 'class': 'compliance', 'tests': {},
                           'evaluate': {'assessment': 'a-assessment'}}}
        with self.assertRaisesRegex(ValueError, 'cycle'):
            verify_published_inventory(cyclic)

    def test_shared_fact_and_rule_reference_resolution(self):
        cpe_root = ET.parse(FIXTURES / 'linux-platform.xml').getroot()
        benchmark = ET.Element(f'{{{XCCDF}}}Benchmark')
        ET.SubElement(benchmark, f'{{{XCCDF}}}platform', {'idref': '#fixture-linux-platform'})
        group = ET.SubElement(benchmark, f'{{{XCCDF}}}Group')
        rule = ET.SubElement(group, f'{{{XCCDF}}}Rule', {'id': 'fixture-rule'})
        ET.SubElement(rule, f'{{{XCCDF}}}platform', {'idref': '#fixture-linux-platform'})
        source_root = ET.Element('root')
        source_root.append(cpe_root)
        source = SimpleNamespace(
            root=source_root, benchmark=benchmark, rules={'fixture-rule': rule},
            parents={group: benchmark, rule: group}, catalog={'linux-oval.xml': 'oval-linux'},
        )
        # Source node is sufficient for the converter stub; this test exercises
        # graph lowering, not OVAL capability semantics.
        definition = ET.Element(f'{{{OVAL}}}definition', {'id': 'unused', 'class': 'compliance'})
        source.node = lambda component, identifier, kind: definition
        docs = {
            'authoring/direct-slice/benchmark.json': {'benchmark': {
                'platform': {'id': 'fixture', 'title': 'fixture', 'applicability': {}},
            }},
            'authoring/direct-slice/rules/fixture-rule.json': {'rule': {'applicability': []}},
        }
        coverage = {'rules': [{'source_rule': 'fixture-rule', 'status': 'converted',
                               'artifacts': ['authoring/direct-slice/rules/fixture-rule.json']}]}

        def fake_assessment(*args, **kwargs):
            aid = args[3]
            return ({'assessment': {'id': aid, 'version': 1, 'assessment_title': 'fact',
                                    'mode': 'automated', 'class': 'compliance',
                                    'specification': {'id': 'fixture', 'version': '0.4'},
                                    'tests': {}, 'evaluate': {'not_evaluated': {'reason': 'fixture'}}}},
                    {'assessment': aid, 'source_fact_ref': kwargs.get('source_fact')})

        with patch('scap_ng_tools.converter.applicability._assessment_document', fake_assessment):
            documents, trace = build_applicability(source, docs, coverage, mappings=[])
        self.assertEqual(trace['source_rule_count_attached'], 1)
        self.assertEqual(trace['shared_assessment_count'], 5)  # 3 facts + OR + AND platform
        catalog = documents['authoring/direct-slice/applicability.json']['applicability']
        self.assertEqual(len(catalog['conditions']), 1)
        self.assertEqual(documents['authoring/direct-slice/rules/fixture-rule.json']['rule']['applicability'], list(catalog['conditions']))
        self.assertEqual(documents['authoring/direct-slice/benchmark.json']['benchmark']['platform']['applicability']['conditions'], list(catalog['conditions']))
        emitted = {d['assessment']['id'] for p, d in documents.items() if '/assessments/' in p}
        self.assertTrue(set(v['assessment'] for v in catalog['conditions'].values()) <= emitted)


if __name__ == '__main__':
    unittest.main()
