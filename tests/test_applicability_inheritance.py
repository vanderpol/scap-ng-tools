import unittest
import xml.etree.ElementTree as ET

from scap_ng_tools.converter._v04_runtime.v04_direct_scap_source import SourceModel, XCCDF

X = '{' + XCCDF + '}'

class ApplicabilityInheritance(unittest.TestCase):
    def test_nested_groups_keep_levels_separate(self):
        benchmark = ET.fromstring(f'''<Benchmark xmlns="{XCCDF}" id="b">
          <platform idref="cpe:/o:vendor:os"/>
          <Group id="outer"><platform idref="#outer-platform"/>
            <Group id="inner"><platform idref="#inner-platform"/>
              <Rule id="rule-1"><platform idref="#rule-platform"/></Rule>
            </Group>
          </Group>
        </Benchmark>''')
        source = SourceModel.__new__(SourceModel)
        source.benchmark = benchmark
        rule = benchmark.find('.//' + X + 'Rule')
        source.parents = {child: parent for parent in benchmark.iter() for child in parent}
        context = source.applicability_context(rule)
        self.assertEqual([level['kind'] for level in context['levels']], ['benchmark', 'group', 'group', 'rule'])
        self.assertEqual([[c['source_idref'] for c in level['conditions']] for level in context['levels']], [
            ['cpe:/o:vendor:os'], ['#outer-platform'], ['#inner-platform'], ['#rule-platform']])
        # The old bug's flattened list does not exist in the corrected context.
        self.assertNotIn('platforms', context)

    def test_multiple_platform_children_are_a_local_or_set(self):
        benchmark = ET.fromstring(f'''<Benchmark xmlns="{XCCDF}" id="b">
          <Group id="g"><Rule id="r"><platform idref="#a"/><platform idref="#b"/></Rule></Group>
        </Benchmark>''')
        source = SourceModel.__new__(SourceModel)
        source.benchmark = benchmark
        rule = benchmark.find('.//' + X + 'Rule')
        source.parents = {child: parent for parent in benchmark.iter() for child in parent}
        level = source.applicability_level(rule)
        self.assertEqual(level['operator'], 'any_of')
        self.assertEqual([c['source_idref'] for c in level['conditions']], ['#a', '#b'])

    def test_cpe_logical_test_is_retained_as_a_boolean_tree(self):
        cpe = ET.fromstring('''<platform-specification xmlns="http://cpe.mitre.org/language/2.0">
          <platform id="nested"><logical-test operator="AND" negate="true">
            <logical-test operator="OR" negate="false"><fact-ref system="oval" id-ref="a"/><fact-ref system="oval" id-ref="b"/></logical-test>
          </logical-test></platform></platform-specification>''')
        source = SourceModel.__new__(SourceModel)
        source.components = {'cpe': cpe}
        tree = source.cpe_platform_expression('#nested')
        self.assertEqual(tree['operator'], 'AND')
        self.assertTrue(tree['negate'])
        self.assertEqual(tree['operands'][0]['operator'], 'OR')
        self.assertEqual([x['fact_ref']['id-ref'] for x in tree['operands'][0]['operands']], ['a', 'b'])

if __name__ == '__main__':
    unittest.main()
