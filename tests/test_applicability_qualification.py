import hashlib
import json
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
X = '{http://checklists.nist.gov/xccdf/1.2}'

class ApplicabilityQualificationEvidence(unittest.TestCase):
    def test_standalone_fixture_has_all_source_levels_and_profile(self):
        path = ROOT / 'tests/fixtures/applicability/qualification-levels.xccdf.xml'
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                         'c4835cb9f10c34b4897199af74eb51049c9aa33b89b9f59ed4419692100c7f01')
        benchmark = ET.parse(path).getroot()
        groups = benchmark.findall(f'.//{X}Group')
        rules = benchmark.findall(f'.//{X}Rule')
        self.assertEqual(len(benchmark.findall(f'{X}platform')), 1)
        self.assertEqual(len(groups), 2)
        self.assertEqual(len(groups[0].findall(f'{X}Group')), 1)
        self.assertEqual(len(rules), 4)
        self.assertTrue(all(rule.findall(f'{X}platform') for rule in rules))
        self.assertEqual(len(benchmark.findall(f'{X}Profile')), 1)

    def test_matrix_separates_real_corpus_and_synthetic_fixture(self):
        matrix = json.loads((ROOT / 'docs/evidence/applicability-qualification/qualification-matrix.json').read_text())
        evidence = {item['id']: item for item in matrix['evidence']}
        self.assertEqual(evidence['windows11-r700']['kind'], 'real_source')
        self.assertEqual(evidence['pinned-65-corpus']['group_platform_declarations'], 0)
        self.assertEqual(evidence['standalone-level-fixture']['kind'], 'synthetic_standards_conformant')
        self.assertEqual(evidence['standalone-level-fixture']['ri_results']['profile_disabled'], 'not_evaluated')

if __name__ == '__main__':
    unittest.main()
