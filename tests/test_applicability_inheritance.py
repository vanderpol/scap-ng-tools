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

    def test_colliding_platform_idrefs_preserve_independent_catalog_ids(self):
        # Both case folding and punctuation normalization used to lose an
        # independent XCCDF platform reference through catalog.setdefault.
        for refs in (
                ('#Linux', '#linux'),
                ('#product.foo', '#product-foo'),
                ('#' + 'Product' * 12 + '.x',
                 '#' + 'Product' * 12 + '-x')):
            with self.subTest(refs=refs):
                root = ET.Element(X + 'Benchmark', {'id': 'b'})
                elements = [ET.SubElement(root, X + 'platform', {'idref': ref})
                            for ref in refs]
                source = SourceModel.__new__(SourceModel)
                source.benchmark = root
                source.components = {}
                ids = [source.applicability_condition_id(element) for element in elements]
                self.assertEqual(len(set(ids)), 2)
                self.assertTrue(all(len(identifier) <= 64 for identifier in ids))
                self.assertEqual([source.applicability_condition_id(element)
                                  for element in elements], ids)
                catalog = source.applicability_catalog()
                self.assertEqual(len(catalog), 2)
                self.assertEqual({row['source']['idref'] for row in catalog.values()},
                                 set(refs))

    def test_repeated_exact_platform_reference_keeps_same_identity(self):
        root = ET.Element(X + 'Benchmark', {'id': 'b'})
        first = ET.SubElement(root, X + 'platform', {'idref': '#same'})
        group = ET.SubElement(root, X + 'Group', {'id': 'g'})
        second = ET.SubElement(group, X + 'platform', {'idref': '#same'})
        source = SourceModel.__new__(SourceModel)
        source.benchmark = root
        source.components = {}
        self.assertEqual(source.applicability_condition_id(first),
                         source.applicability_condition_id(second))
        self.assertEqual(len(source.applicability_catalog()), 1)

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
