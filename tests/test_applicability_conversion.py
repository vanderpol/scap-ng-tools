import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET
from types import SimpleNamespace
from unittest.mock import patch

from scap_ng_tools.converter.applicability import (
    _make_composite, build_applicability, extract_platform_specifications,
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
