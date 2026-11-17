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
from scap_ng_tools.converter.direct04 import load_runtime
from scap_ng_tools.converter._v04_runtime.v04_direct_scap_source import SourceModel


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

    def test_nested_group_conversion_uses_rule_id_and_keeps_local_applicability(self):
        benchmark = ET.fromstring(f'''<Benchmark xmlns="{XCCDF}" id="b">
          <Group id="outer"><platform idref="#outer-platform">
            </platform><Group id="inner"><platform idref="#inner-platform"/>
              <Rule id="fixture-rule"><platform idref="#rule-platform"/></Rule>
            </Group>
          </Group>
        </Benchmark>''')
        source = SourceModel.__new__(SourceModel)
        source.benchmark = benchmark
        source.parents = {child: parent for parent in benchmark.iter() for child in parent}
        source.applicability_level = SourceModel.applicability_level.__get__(source)
        rendered = load_runtime().native_group(source, benchmark.find(f'{{{XCCDF}}}Group'),
                                {'fixture-rule': 'native-rule-id'})
        self.assertEqual(rendered['rules'], [])
        self.assertEqual(len(rendered['groups']), 1)
        inner = rendered['groups'][0]
        self.assertEqual(inner['rules'], ['native-rule-id'])
        self.assertEqual([c['condition'] for c in inner['applicability']['any_of']],
                         ['platform-inner-platform-condition'])
        self.assertEqual(rendered['applicability']['any_of'][0]['condition'],
                         'platform-outer-platform-condition')

    def test_distinct_normalized_platform_refs_get_distinct_condition_ids(self):
        # ``#Linux`` and ``#linux`` normalize to the same historical stem.
        # They are nevertheless distinct source references and must not share
        # a catalog condition or provenance record.
        benchmark = ET.fromstring(f'''<Benchmark xmlns="{XCCDF}" id="b">
          <platform idref="#Linux"/>
          <platform idref="#linux"/>
          <Rule id="fixture-rule"/>
        </Benchmark>''')
        rule = benchmark.find(f'{{{XCCDF}}}Rule')
        source = SimpleNamespace(root=benchmark, benchmark=benchmark,
                                 rules={'fixture-rule': rule},
                                 parents={rule: benchmark}, catalog={})
        source.applicability_condition_id = SourceModel.applicability_condition_id.__get__(source)
        source.applicability_level = SourceModel.applicability_level.__get__(source)
        source.applicability_context = SourceModel.applicability_context.__get__(source)
        docs = {
            'authoring/direct-slice/benchmark.json': {'benchmark': {
                'platform': {'id': 'fixture', 'title': 'fixture'}}},
            'authoring/direct-slice/rules/fixture-rule.json': {'rule': {}},
        }
        coverage = {'rules': [{'source_rule': 'fixture-rule', 'status': 'converted',
                               'artifacts': ['authoring/direct-slice/rules/fixture-rule.json']}]}
        documents, trace = build_applicability(source, docs, coverage, mappings=[])
        conditions = documents['authoring/direct-slice/applicability.json']['applicability']['conditions']
        self.assertEqual(len(conditions), 2)
        self.assertEqual({value['source']['idref'] for value in conditions.values()},
                         {'#Linux', '#linux'})
        self.assertEqual(len(set(conditions)), 2)
        self.assertTrue(all(len(key) <= 64 for key in conditions))
        self.assertEqual(trace['source_identity_preserved'], True)

    def test_unqualified_platform_is_provenance_hold_without_synthetic_assessment(self):
        benchmark = ET.fromstring(f'''<Benchmark xmlns="{XCCDF}" id="b">
          <platform idref="cpe:/o:unknown:platform"/>
          <Rule id="fixture-rule"/>
        </Benchmark>''')
        rule = benchmark.find(f'{{{XCCDF}}}Rule')
        source = SimpleNamespace(root=benchmark, benchmark=benchmark, rules={'fixture-rule': rule},
                                parents={rule: benchmark}, catalog={})
        docs = {
            'authoring/direct-slice/benchmark.json': {'benchmark': {
                'platform': {'id': 'fixture', 'title': 'fixture'}}},
            'authoring/direct-slice/rules/fixture-rule.json': {'rule': {}}
        }
        coverage = {'rules': [{'source_rule': 'fixture-rule', 'status': 'converted',
                               'artifacts': ['authoring/direct-slice/rules/fixture-rule.json']}]}
        documents, trace = build_applicability(source, docs, coverage, mappings=[])
        catalog = documents['authoring/direct-slice/applicability.json']['applicability']
        condition = next(iter(catalog['conditions'].values()))
        self.assertNotIn('assessment', condition)
        self.assertEqual(condition['source']['kind'], 'cpe_platform')
        self.assertEqual(condition['source']['id'], 'cpe:/o:unknown:platform')
        self.assertFalse([path for path in documents if '/assessments/' in path])
        self.assertTrue(trace['unsupported'])

    def test_shared_fact_and_rule_reference_resolution(self):
        cpe_root = ET.parse(FIXTURES / 'linux-platform.xml').getroot()
        benchmark = ET.Element(f'{{{XCCDF}}}Benchmark')
        ET.SubElement(benchmark, f'{{{XCCDF}}}platform', {'idref': '#fixture-linux-platform'})
        group = ET.SubElement(benchmark, f'{{{XCCDF}}}Group')
        ET.SubElement(group, f'{{{XCCDF}}}platform', {'idref': '#fixture-linux-platform'})
        rule = ET.SubElement(group, f'{{{XCCDF}}}Rule', {'id': 'fixture-rule'})
        ET.SubElement(rule, f'{{{XCCDF}}}platform', {'idref': '#fixture-linux-platform'})
        source_root = ET.Element('root')
        source_root.append(cpe_root)
        source = SimpleNamespace(
            root=source_root, benchmark=benchmark, rules={'fixture-rule': rule},
            parents={group: benchmark, rule: group}, catalog={'linux-oval.xml': 'oval-linux'},
        )
        source.applicability_condition_id = SourceModel.applicability_condition_id.__get__(source)
        source.applicability_level = SourceModel.applicability_level.__get__(source)
        source.applicability_context = SourceModel.applicability_context.__get__(source)
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
        rule_expression = documents['authoring/direct-slice/rules/fixture-rule.json']['rule']['applicability']
        self.assertEqual([item['condition'] for item in rule_expression['any_of']],
                         ['platform-fixture-linux-platform-condition'])
        benchmark_expression = documents['authoring/direct-slice/benchmark.json']['benchmark']['platform']['applicability']
        self.assertEqual([item['condition'] for item in benchmark_expression['any_of']],
                         ['platform-fixture-linux-platform-condition'])
        levels = coverage['rules'][0]['applicability']['levels']
        self.assertEqual([level['kind'] for level in levels], ['benchmark', 'group', 'rule'])
        self.assertTrue(all('source' in value for value in catalog['conditions'].values()))
        emitted = {d['assessment']['id'] for p, d in documents.items() if '/assessments/' in p}
        self.assertTrue(set(v['assessment'] for v in catalog['conditions'].values()) <= emitted)


if __name__ == '__main__':
    unittest.main()
