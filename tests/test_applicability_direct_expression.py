"""Owner-approved CPE Boolean lowering: no synthetic zero-Test Assessments."""
import unittest
import xml.etree.ElementTree as ET
from types import SimpleNamespace
from unittest.mock import patch

from scap_ng_tools.converter.applicability import (
    build_applicability, extract_platform_specifications,
)
from scap_ng_tools.converter._v04_runtime.v04_direct_scap_source import SourceModel, source_native_identifier

XCCDF = 'http://checklists.nist.gov/xccdf/1.2'
CPE = 'http://cpe.mitre.org/language/2.0'
OVAL = 'http://oval.mitre.org/XMLSchema/oval-definitions-5'


def source_for(cpe_xml, *, ref='#ftp', group_ref=None, rule_ref=None):
    benchmark_platform = '' if ref is None else f'<platform idref="{ref}"/>'
    group_platform = '' if group_ref is None else f'<platform idref="{group_ref}"/>'
    rule_platform = '' if rule_ref is None else f'<platform idref="{rule_ref}"/>'
    benchmark_xml = f'''<Benchmark xmlns="{XCCDF}" id="b">
      {benchmark_platform}<Group id="g">{group_platform}<Rule id="r">{rule_platform}</Rule></Group>
    </Benchmark>'''
    benchmark = ET.fromstring(benchmark_xml)
    cpe = ET.fromstring(cpe_xml)
    rule = benchmark.find(f'.//{{{XCCDF}}}Rule')
    group = benchmark.find(f'.//{{{XCCDF}}}Group')
    source = SimpleNamespace(
        root=ET.Element('root'), benchmark=benchmark, rules={'r': rule},
        parents={group: benchmark, rule: group}, catalog={'oval.xml': 'oval'},
        applicability_condition_id=lambda node: 'platform-' + node.get('idref').lstrip('#') + '-condition',
    )
    source.applicability_level = lambda item: (
        {'kind': item.tag.rsplit('}', 1)[-1].lower(), 'id': item.get('id'),
         'operator': 'any_of',
         'conditions': [{'id': 'unused', 'source_idref': x.get('idref')}
                        for x in item.findall(f'{{{XCCDF}}}platform')]}
        if item.findall(f'{{{XCCDF}}}platform') else None)
    source.applicability_context = lambda item: {
        'levels': [x for x in (source.applicability_level(benchmark),
                               source.applicability_level(group),
                               source.applicability_level(rule)) if x],
        'effective_operator': 'all_of'}
    source.node = lambda component, identifier, kind: ET.Element(
        f'{{{OVAL}}}definition', {'id': identifier, 'class': 'inventory'})
    source.root.append(cpe)
    return source


class DirectApplicabilityExpressions(unittest.TestCase):
    def fake_fact(self, *args, **kwargs):
        aid = args[3]
        return ({'assessment': {'id': aid, 'version': 1, 'assessment_title': 'fact',
                                'mode': 'automated', 'class': 'inventory',
                                'specification': {'id': 'fixture', 'version': '0.4.1'},
                                'tests': {'fact-test': {}},
                                'evaluate': {'not_evaluated': {'reason': 'fixture'}}}},
                {'assessment': aid})

    def run_tree(self, logical, title='FTP'):
        cpe = ET.tostring(ET.fromstring(
            f'<platform xmlns="{CPE}" id="ftp"><title>{title}</title>{logical}</platform>'),
            encoding='unicode')
        source = source_for(cpe)
        docs = {'authoring/direct-slice/benchmark.json': {'benchmark': {'platform': {'id': 'b'}}},
                'authoring/direct-slice/rules/r.json': {'rule': {}}}
        coverage = {'rules': [{'source_rule': 'r', 'status': 'converted',
                               'artifacts': ['authoring/direct-slice/rules/r.json']}]}
        with patch('scap_ng_tools.converter.applicability._assessment_document', self.fake_fact):
            return build_applicability(source, docs, coverage, mappings=[])

    def test_fact_condition_ids_use_xccdf_platform_title(self):
        docs, _ = self.run_tree(
            '<logical-test operator="AND" negate="false">'
            '<check-fact-ref system="oval" href="oval.xml" id-ref="oval:def:201"/>'
            '</logical-test>',
            title='Windows Not Server Core Installation')
        conditions = docs['authoring/direct-slice/applicability.json']
        condition_id = next(iter(conditions['applicability']['conditions']))
        self.assertRegex(
            condition_id,
            r'^platform-windows-not-server-core-installation-[0-9a-f]{8}-condition$')
        self.assertNotIn('applicability-fact', condition_id)
        self.assertLessEqual(len(condition_id), 64)
        condition = conditions['applicability']['conditions'][condition_id]
        self.assertEqual(condition['source']['idref'], 'oval:def:201')

        # A platform title is a label, not a condition identity. Distinct
        # source facts under the same title must remain distinct while still
        # retaining the same readable stem.
        docs, _ = self.run_tree(
            '<logical-test operator="OR" negate="false">'
            '<check-fact-ref system="oval" href="oval.xml" id-ref="oval:def:201"/>'
            '<check-fact-ref system="oval" href="oval.xml" id-ref="oval:def:202"/>'
            '</logical-test>',
            title='Windows Not Server Core Installation')
        conditions = docs['authoring/direct-slice/applicability.json']['applicability']['conditions']
        self.assertEqual(len(conditions), 2)
        self.assertEqual({value['source']['idref'] for value in conditions.values()},
                         {'oval:def:201', 'oval:def:202'})
        self.assertTrue(all(key.startswith('platform-windows-not-server-core-installation-')
                            for key in conditions))

    def test_negated_singleton_is_direct_not_at_consumer_scope(self):
        docs, trace = self.run_tree(
            '<logical-test operator="AND" negate="true">'
            '<check-fact-ref system="oval" href="oval.xml" id-ref="oval:def:ftp"/>'
            '</logical-test>')
        expr = docs['authoring/direct-slice/benchmark.json']['benchmark']['platform']['applicability']
        self.assertEqual(set(expr), {'not'})
        self.assertEqual(len(trace['shared_assessments']), 1)
        self.assertEqual(sum(1 for p in docs if '/assessments/' in p), 1)
        assessment = next(d['assessment'] for p, d in docs.items() if '/assessments/' in p)
        self.assertTrue(assessment['tests'])

    def test_nested_and_or_preserves_expression_and_reuses_facts(self):
        docs, trace = self.run_tree('''<logical-test operator="AND" negate="false">
          <logical-test operator="OR" negate="false">
            <check-fact-ref system="oval" href="oval.xml" id-ref="oval:a"/>
            <check-fact-ref system="oval" href="oval.xml" id-ref="oval:b"/>
          </logical-test>
          <check-fact-ref system="oval" href="oval.xml" id-ref="oval:c"/>
        </logical-test>''')
        expr = docs['authoring/direct-slice/benchmark.json']['benchmark']['platform']['applicability']
        self.assertEqual(set(expr), {'all_of'})
        self.assertTrue(any(set(item) == {'any_of'} for item in expr['all_of']))
        self.assertEqual(len(trace['shared_assessments']), 3)
        self.assertEqual(len(trace['platform_expressions']), 1)

    def test_supported_and_unsupported_siblings_remain_explicit_tree_leaves(self):
        logical = ('<logical-test operator="OR" negate="false">'
                   '<check-fact-ref system="oval" href="oval.xml" id-ref="oval:good"/>'
                   '<check-fact-ref system="oval" href="oval.xml" id-ref="oval:bad"/>'
                   '</logical-test>')
        cpe = f'<platform xmlns="{CPE}" id="ftp"><title>FTP</title>{logical}</platform>'
        source = source_for(cpe)
        docs = {'authoring/direct-slice/benchmark.json': {'benchmark': {'platform': {'id': 'b'}}},
                'authoring/direct-slice/rules/r.json': {'rule': {}}}
        coverage = {'rules': [{'source_rule': 'r', 'status': 'converted',
                               'artifacts': ['authoring/direct-slice/rules/r.json']}]}
        def fact(*args, **kwargs):
            if args[2] == 'oval:bad':
                raise ValueError('unsupported bad fact')
            return self.fake_fact(*args, **kwargs)
        with patch('scap_ng_tools.converter.applicability._assessment_document', side_effect=fact):
            docs, trace = build_applicability(source, docs, coverage, mappings=[])
        expr = docs['authoring/direct-slice/benchmark.json']['benchmark']['platform']['applicability']
        self.assertEqual(set(expr), {'any_of'})
        self.assertEqual(len(expr['any_of']), 2)
        conditions = docs['authoring/direct-slice/applicability.json']['applicability']['conditions']
        self.assertEqual(sum('assessment' in value for value in conditions.values()), 1)
        self.assertEqual(len(trace['shared_assessments']), 1)
        self.assertTrue(any('unsupported bad fact' in row['reason'] for row in trace['unsupported']))

    def test_source_operand_order_is_preserved(self):
        logical = ('<logical-test operator="AND" negate="false">'
                   '<check-fact-ref system="oval" href="oval.xml" id-ref="oval:first"/>'
                   '<logical-test operator="OR" negate="false">'
                   '<check-fact-ref system="oval" href="oval.xml" id-ref="oval:second"/>'
                   '<check-fact-ref system="oval" href="oval.xml" id-ref="oval:third"/>'
                   '</logical-test></logical-test>')
        docs, _ = self.run_tree(logical)
        expr = docs['authoring/direct-slice/benchmark.json']['benchmark']['platform']['applicability']
        self.assertEqual(list(expr), ['all_of'])
        self.assertEqual(set(expr['all_of'][0]), {'condition'})
        self.assertEqual(set(expr['all_of'][1]), {'any_of'})

    def test_cpe_lowering_has_bounded_nesting(self):
        root = ET.Element(f'{{{CPE}}}platform', {'id': 'deep'})
        parent = root
        for _ in range(66):
            parent = ET.SubElement(parent, f'{{{CPE}}}logical-test', {'operator': 'AND'})
        with self.assertRaisesRegex(ValueError, 'nesting exceeds'):
            extract_platform_specifications(SimpleNamespace(root=root))

    def test_fact_status_and_nonempty_evidence_are_preserved(self):
        docs, trace = self.run_tree(
            '<logical-test operator="AND" negate="true">'
            '<check-fact-ref system="oval" href="oval.xml" id-ref="oval:def:ftp"/>'
            '</logical-test>')
        assessment = next(d['assessment'] for p, d in docs.items() if '/assessments/' in p)
        self.assertTrue(assessment['tests'], 'a reusable fact must collect real evidence')
        # The direct lowering moves only the source Boolean operator; it does
        # not rewrite a fact's unknown/not-evaluated result.
        self.assertEqual(assessment['evaluate'], {'not_evaluated': {'reason': 'fixture'}})
        self.assertFalse(trace['unsupported'])

    def test_failed_fact_is_explicit_error_hold_without_wrapper(self):
        source = source_for(
            '<platform xmlns="%s" id="ftp"><title>FTP</title>'
            '<logical-test operator="AND" negate="false">'
            '<check-fact-ref system="oval" href="oval.xml" id-ref="oval:def:ftp"/>'
            '</logical-test></platform>' % CPE)
        docs = {'authoring/direct-slice/benchmark.json': {'benchmark': {'platform': {'id': 'b'}}},
                'authoring/direct-slice/rules/r.json': {'rule': {}}}
        coverage = {'rules': [{'source_rule': 'r', 'status': 'converted',
                               'artifacts': ['authoring/direct-slice/rules/r.json']}]}
        with patch('scap_ng_tools.converter.applicability._assessment_document',
                   side_effect=ValueError('collector unsupported')):
            docs, trace = build_applicability(source, docs, coverage, mappings=[])
        condition = next(iter(
            docs['authoring/direct-slice/applicability.json']['applicability']['conditions'].values()))
        self.assertNotIn('assessment', condition)
        self.assertTrue(any('collector unsupported' in row['reason']
                            for row in trace['unsupported']))
        self.assertFalse([p for p in docs if '/assessments/' in p])

    def test_inherited_expression_is_attached_at_group_not_flattened_to_rule(self):
        cpe = ('<platform xmlns="%s" id="ftp"><title>FTP</title>'
               '<logical-test operator="AND" negate="true">'
               '<check-fact-ref system="oval" href="oval.xml" id-ref="oval:def:ftp"/>'
               '</logical-test></platform>') % CPE
        source = source_for(cpe, ref=None, group_ref='#ftp')
        docs = {'authoring/direct-slice/benchmark.json': {'benchmark': {
                    'platform': {'id': 'b'},
                    'groups': [{'id': source_native_identifier('g', 'group-'), 'groups': [], 'rules': []}]}},
                'authoring/direct-slice/rules/r.json': {'rule': {}}}
        coverage = {'rules': [{'source_rule': 'r', 'status': 'converted',
                               'artifacts': ['authoring/direct-slice/rules/r.json']}]}
        with patch('scap_ng_tools.converter.applicability._assessment_document', self.fake_fact):
            docs, trace = build_applicability(source, docs, coverage, mappings=[])
        group = docs['authoring/direct-slice/benchmark.json']['benchmark']['groups'][0]
        condition_id = next(iter(
            docs['authoring/direct-slice/applicability.json']['applicability']['conditions']))
        self.assertEqual(group['applicability'], {'not': {'condition': condition_id}})
        self.assertNotIn('applicability', docs['authoring/direct-slice/rules/r.json']['rule'])
        self.assertEqual(trace['source_rule_count_attached'], 1)

    def test_one_and_xor_are_explicit_holds_without_wrapper_assessment(self):
        for operator in ('ONE', 'XOR'):
            docs, trace = self.run_tree(
                f'<logical-test operator="{operator}" negate="false">'
                '<check-fact-ref system="oval" href="oval.xml" id-ref="oval:a"/>'
                '<check-fact-ref system="oval" href="oval.xml" id-ref="oval:b"/>'
                '</logical-test>')
            self.assertEqual(
                docs['authoring/direct-slice/benchmark.json']['benchmark']['platform']['applicability'],
                {'condition': 'platform-ftp-condition'})
            self.assertTrue(any('no lossless canonical' in row['reason']
                                for row in trace['unsupported']))
            self.assertEqual(len(trace['shared_assessments']), 2)


if __name__ == '__main__':
    unittest.main()
